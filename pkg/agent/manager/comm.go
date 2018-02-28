package manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
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
	conn   *grpc.ClientConn
	stream node.Node_FetchSVIDClient
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

	stream, err := nodeClient.FetchSVID(context.Background())
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &client{conn: conn, stream: stream}, nil
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
	c.stream.CloseSend()
	c.conn.Close()
}

type update struct {
	regEntries map[string]*common.RegistrationEntry
	svids      map[string]*node.Svid
	lastBundle []byte
}

func (c *client) sendAndReceive(req *node.FetchSVIDRequest) (*update, error) {
	err := c.stream.Send(req)
	if err != nil {
		// TODO: should we try to create a new stream?
		//m.shutdown(err)
		return nil, err
	}

	regEntries := map[string]*common.RegistrationEntry{}
	svids := map[string]*node.Svid{}
	var lastBundle []byte
	for {
		resp, err := c.stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			// TODO: should we try to create a new stream?
			//m.shutdown(err)
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
