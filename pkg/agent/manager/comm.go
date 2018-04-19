package manager

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	spiffe_tls "github.com/spiffe/go-spiffe/tls"
	"github.com/spiffe/spire/pkg/common/grpcutil"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type client struct {
	log logrus.FieldLogger
	// Mutex used to pipeline requests to fecthUpdates function.
	requests   *sync.Mutex
	conn       *grpc.ClientConn
	nodeClient node.NodeClient

	svid *x509.Certificate
	key  *ecdsa.PrivateKey
}

type clientsPool struct {
	// Map of client connections to the server keyed by SPIFFEID (there is a special case
	// where the key is a string that identifies the client used for SVID rotation).
	clients map[string]*client
	// Protects access to the pool.
	m *sync.Mutex
}

type update struct {
	regEntries map[string]*common.RegistrationEntry
	svids      map[string]*node.Svid
	lastBundle []byte
}

func (c *client) fetchUpdates(req *node.FetchSVIDRequest) (*update, error) {
	c.requests.Lock()
	defer c.requests.Unlock()

	stream, err := c.nodeClient.FetchSVID(context.Background())
	// We weren't able to get a stream...close the client and return the error.
	if err != nil {
		c.close()
		c.log.Errorf("%v: %v", ErrUnableToGetStream, err)
		return nil, ErrUnableToGetStream
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
			regEntries[re.EntryId] = re
		}
		for spiffeid, svid := range resp.SvidUpdate.Svids {
			svids[spiffeid] = svid
		}
		lastBundle = resp.SvidUpdate.Bundle
	}
	return &update{regEntries, svids, lastBundle}, nil
}

func (c *client) close() {
	if c.conn != nil {
		c.nodeClient = nil
		c.conn.Close()
		c.conn = nil
	}
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

// close releases the pool's resources.
func (p *clientsPool) close() {
	p.m.Lock()
	defer p.m.Unlock()
	for _, c := range p.clients {
		c.close()
	}
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

func (m *manager) newGRPCConn(svid *x509.Certificate, key *ecdsa.PrivateKey) (*grpc.ClientConn, error) {
	var tlsCert []tls.Certificate
	var tlsConfig *tls.Config

	spiffePeer := &spiffe_tls.TLSPeer{
		SpiffeIDs:  []string{m.serverSPIFFEID},
		TrustRoots: m.bundleAsCertPool(),
	}
	tlsCert = append(tlsCert, tls.Certificate{Certificate: [][]byte{svid.Raw}, PrivateKey: key})
	tlsConfig = spiffePeer.NewTLSConfig(tlsCert)
	credFunc := func() (credentials.TransportCredentials, error) { return  credentials.NewTLS(tlsConfig), nil }

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // TODO: Make this timeout configurable?
	defer cancel()

	config := grpcutil.GRPCDialerConfig{
		Log:   m.c.Log,
		CredFunc: credFunc,
	}
	dialer := grpcutil.NewGRPCDialer(config)
	conn, err := dialer.Dial(ctx, m.serverAddr)
	if err != nil {
		spiffeID, _ := getSpiffeIDFromSVID(svid)
		return nil, fmt.Errorf("cannot create connection for spiffeID %s: %v", spiffeID, err)
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

	return &client{
		log:        m.c.Log,
		requests:   &sync.Mutex{},
		conn:       conn,
		nodeClient: nodeClient,
		svid:       svid,
		key:        key,
	}, nil
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

func (m *manager) ensureRotationClient() (*client, error) {
	currentCli := m.syncClients.get(rotatorTag)
	if currentCli == nil {
		return nil, fmt.Errorf("no client found for rotator")
	}

	if currentCli.conn != nil {
		return currentCli, nil
	}

	svid, key := m.getBaseSVIDEntry()
	newCli, err := m.newClient(svid, key)
	if err != nil {
		return nil, err
	}
	m.syncClients.add(rotatorTag, newCli)
	return newCli, nil
}

func (m *manager) ensureSyncClient(spiffeID string) (*client, error) {
	currentCli := m.syncClients.get(spiffeID)
	if currentCli == nil {
		return nil, fmt.Errorf("no client found for %s", spiffeID)
	}

	if currentCli.conn != nil {
		return currentCli, nil
	}

	newCli, err := m.newClient(currentCli.svid, currentCli.key)
	if err != nil {
		return nil, err
	}
	m.syncClients.add(spiffeID, newCli)
	return newCli, nil
}
