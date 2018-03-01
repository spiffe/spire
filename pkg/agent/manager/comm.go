package manager

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/common"
	"io"
	"sync"
	"time"

	spiffe_tls "github.com/spiffe/go-spiffe/tls"
	"github.com/spiffe/spire/proto/api/node"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type client struct {
	// Channel used to as a requests pipeline.
	requests   chan *node.FetchSVIDRequest
	conn       *grpc.ClientConn
	nodeClient node.NodeClient
}

type clientsPool struct {
	// Map of client connections to the server keyed by SPIFFEID (there is a special case
	// where the key is a string that identifies the client used for SVID rotation).
	clients map[string]*client
	// Protects access to the pool.
	m *sync.Mutex
}

func (m *manager) newGRPCConn(svid *x509.Certificate, key *ecdsa.PrivateKey) (*grpc.ClientConn, error) {
	var tlsCert []tls.Certificate
	var tlsConfig *tls.Config

	spiffePeer := &spiffe_tls.TLSPeer{
		SpiffeIDs:  []string{m.serverSPIFFEID},
		TrustRoots: m.bundleAsCertPool(),
	}
	tlsCert = append(tlsCert, tls.Certificate{Certificate: [][]byte{svid.Raw}, PrivateKey: key})
	tlsConfig = spiffePeer.NewTLSConfig(tlsCert)
	dialCreds := grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))

	// We don't need cancel, so discard it.
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second) // TODO: Make this timeout configurable?
	conn, err := grpc.DialContext(ctx, m.serverAddr.String(), dialCreds)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// newClient creates a client.
func (m *manager) newClient(svid *x509.Certificate, key *ecdsa.PrivateKey) (*client, error) {
	conn, err := m.newGRPCConn(svid, key)
	if err != nil {
		return nil, err
	}
	nodeClient := node.NewNodeClient(conn)

	return &client{requests: make(chan *node.FetchSVIDRequest), conn: conn, nodeClient: nodeClient}, nil
}

// newClient adds a new client to the pool and associates it to the specified list of spiffeIDs.
func (m *manager) newSyncClient(spiffeIDs []string, svid *x509.Certificate, key *ecdsa.PrivateKey) error {
	// If there is no pool yet, create one.
	m.mtx.Lock()
	if m.syncClients == nil {
		m.syncClients = &clientsPool{clients: map[string]*client{}, m: &sync.Mutex{}}
	}
	m.mtx.Unlock()

	client, err := m.newClient(svid, key)
	if err != nil {
		return err
	}

	for _, id := range spiffeIDs {
		m.syncClients.add(id, client)
	}

	return nil
}

func (p *clientsPool) add(spiffeID string, client *client) {
	// If there is already a connection with the specified spiffeID, close it first.
	if c := p.get(spiffeID); c != nil {
		c.close()
	}

	p.m.Lock()
	defer p.m.Unlock()
	p.clients[spiffeID] = client
}

func (p *clientsPool) get(spiffeID string) *client {
	p.m.Lock()
	defer p.m.Unlock()
	return p.clients[spiffeID]
}

func (m *manager) getRotationClient() *client {
	return m.syncClients.get(rotatorTag)
}

func (m *manager) renewRotatorClient() error {
	svid, key := m.getBaseSVIDEntry()
	c, err := m.newClient(svid, key)
	if err != nil {
		return err
	}
	m.syncClients.add(rotatorTag, c)
	return nil
}

// close releases the pool's resources.
func (p *clientsPool) close() {
	p.m.Lock()
	defer p.m.Unlock()
	for _, c := range p.clients {
		c.close()
	}
}

func (c *client) close() {
	c.conn.Close()
}

type update struct {
	regEntries map[string]*common.RegistrationEntry
	svids      map[string]*node.Svid
	lastBundle []byte
}

func (u *update) String() string {
	var buffer bytes.Buffer
	buffer.WriteString("{ regEntries: [")
	for _, re := range u.regEntries {
		buffer.WriteString("{ spiffeID: ")
		buffer.WriteString(re.SpiffeId)
		buffer.WriteString(", parentID: ")
		buffer.WriteString(re.ParentId)
		buffer.WriteString(", selectors: ")
		buffer.WriteString(fmt.Sprintf("%v", re.Selectors))
		buffer.WriteString("}")
	}
	buffer.WriteString("], svids: [")
	for key, svid := range u.svids {
		buffer.WriteString(key)
		buffer.WriteString(": ")
		buffer.WriteString(svid.String()[:30])
		buffer.WriteString(" ")
	}
	buffer.WriteString("], lastBundle: ")
	if u.lastBundle != nil && len(u.lastBundle) > 0 {
		buffer.WriteString("bytes")
	} else {
		buffer.WriteString("none")
	}
	buffer.WriteString("}")
	return buffer.String()
}

func (c *client) sendAndReceive(r *node.FetchSVIDRequest) (*update, error) {
	// Enable pipelined access by client to this function.
	go func() {
		c.requests <- r
	}()
	req := <-c.requests

	var stream node.Node_FetchSVIDClient
	var err error
	// Create a new stream, we retry some times because under certain conditions
	// the stream cannot be created because it throws an "all SubConns are in TransientFailure"
	// which can be recovered retrying. Some times it is not possible to avoid that error,
	// which could be because the server is down, or because there are some problem with the
	// connection's mTLS configuration.
	for retries := 0; retries < 5; retries++ {
		stream, err = c.nodeClient.FetchSVID(context.Background())
		if err == nil {
			break
		}
	}
	// We weren't able to get a stream...close the client and return the error.
	if err != nil {
		c.close()
		return nil, err
	}
	// Send the request to the server using the stream.
	err = stream.Send(req)
	// Close the stream whether there was an error or not
	stream.CloseSend()
	if err != nil {
		// TODO: should we try to create a new stream?
		return nil, err
	}

	regEntries := map[string]*common.RegistrationEntry{}
	svids := map[string]*node.Svid{}
	var lastBundle []byte
	// Read all the server responses from the stream.
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			if len(regEntries) > 0 || len(svids) > 0 || lastBundle != nil {
				// There was an error receiving a response, exit loop to return what we have.
				return &update{regEntries, svids, lastBundle}, ErrPartialResponse
			}

			return nil, err
		}

		for _, re := range resp.SvidUpdate.RegistrationEntries {
			regEntryKey := util.DeriveRegEntryhash(re)
			regEntries[regEntryKey] = re
		}
		for spiffeid, svid := range resp.SvidUpdate.Svids {
			svids[spiffeid] = svid
		}
		lastBundle = resp.SvidUpdate.Bundle
	}
	return &update{regEntries, svids, lastBundle}, nil
}
