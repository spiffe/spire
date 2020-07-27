package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/url"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/api/node"
	agentpb "github.com/spiffe/spire/proto/spire/api/server/agent/v1"
	bundlepb "github.com/spiffe/spire/proto/spire/api/server/bundle/v1"
	entrypb "github.com/spiffe/spire/proto/spire/api/server/entry/v1"
	svidpb "github.com/spiffe/spire/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
	"google.golang.org/grpc"
)

var (
	ErrUnableToGetStream = errors.New("unable to get a stream")
)

const rpcTimeout = 30 * time.Second

type JWTSVID struct {
	Token     string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type Client interface {
	FetchUpdates(ctx context.Context, req *node.FetchX509SVIDRequest, forRotation bool) (*Update, error)
	FetchJWTSVID(ctx context.Context, jsr *node.JSR, entryID string) (*JWTSVID, error)

	// Release releases any resources that were held by this Client, if any.
	Release()
}

// Config holds a client configuration
type Config struct {
	Addr        string
	Log         logrus.FieldLogger
	TrustDomain url.URL
	// KeysAndBundle is a callback that must return the keys and bundle used by the client
	// to connect via mTLS to Addr.
	KeysAndBundle func() ([]*x509.Certificate, *ecdsa.PrivateKey, []*x509.Certificate)

	// RotMtx is used to prevent the creation of new connections during SVID rotations
	RotMtx *sync.RWMutex

	// Use experimental api
	ExperimentalAPIEnabled bool
}

type client struct {
	c           *Config
	connections *nodeConn
	m           sync.Mutex
	// Constructor used for testing purposes.
	createNewNodeClient   func(grpc.ClientConnInterface) node.NodeClient
	createNewEntryClient  func(grpc.ClientConnInterface) entrypb.EntryClient
	createNewBundleClient func(grpc.ClientConnInterface) bundlepb.BundleClient
	createNewSVIDClient   func(grpc.ClientConnInterface) svidpb.SVIDClient
	createNewAgentClient  func(grpc.ClientConnInterface) agentpb.AgentClient

	// Constructor used for testing purposes.
	dialContext func(ctx context.Context, target string, opts ...grpc.DialOption) (*grpc.ClientConn, error)
}

// New creates a new client struct with the configuration provided
func New(c *Config) Client {
	return newClient(c)
}

func newClient(c *Config) *client {
	return &client{
		c:                     c,
		createNewNodeClient:   node.NewNodeClient,
		createNewEntryClient:  entrypb.NewEntryClient,
		createNewBundleClient: bundlepb.NewBundleClient,
		createNewSVIDClient:   svidpb.NewSVIDClient,
		createNewAgentClient:  agentpb.NewAgentClient,
	}
}

func (c *client) FetchUpdates(ctx context.Context, req *node.FetchX509SVIDRequest, forRotation bool) (*Update, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	if !forRotation {
		c.c.RotMtx.RLock()
		defer c.c.RotMtx.RUnlock()
	}

	if c.c.ExperimentalAPIEnabled {
		resp, err := c.fetchUpdates(ctx, req, forRotation)
		if err != nil {
			c.c.Log.WithError(err).Error("Failed to fetch updates")
			return nil, err
		}
		return resp, nil
	}

	nodeClient, nodeConn, err := c.newNodeClient(ctx)
	if err != nil {
		return nil, err
	}
	defer nodeConn.Release()

	stream, err := nodeClient.FetchX509SVID(ctx)
	// We weren't able to get a stream...close the client and return the error.
	if err != nil {
		c.release(nodeConn)
		c.c.Log.WithError(err).Errorf("Failure fetching X509 SVID. %v", ErrUnableToGetStream)
		return nil, ErrUnableToGetStream
	}

	// Send the request to the server using the stream.
	if err := stream.Send(req); err != nil {
		c.release(nodeConn)
		return nil, errs.Wrap(err)
	}

	if err := stream.CloseSend(); err != nil {
		c.release(nodeConn)
		return nil, errs.Wrap(err)
	}

	regEntries := map[string]*common.RegistrationEntry{}
	svids := map[string]*node.X509SVID{}
	bundles := map[string]*common.Bundle{}
	// Read all the server responses from the stream.
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			c.c.Log.Errorf("failed to consume entire SVID update stream: %v", err)
			c.release(nodeConn)
			return nil, err
		}

		if resp.SvidUpdate == nil {
			c.c.Log.Warn("empty update in SVID update stream")
			continue
		}

		for _, re := range resp.SvidUpdate.RegistrationEntries {
			if err := validateRegistrationEntry(re); err != nil {
				c.c.Log.WithFields(logrus.Fields{
					telemetry.RegistrationID: re.EntryId,
					telemetry.SPIFFEID:       re.SpiffeId,
					telemetry.Selectors:      re.Selectors,
					telemetry.Error:          err.Error(),
				}).Warn("Received malformed entry from SPIRE server")
				continue
			}
			regEntries[re.EntryId] = re
		}
		for entryID, svid := range resp.SvidUpdate.Svids {
			svids[entryID] = svid
		}
		for trustDomainID, bundle := range resp.SvidUpdate.Bundles {
			bundles[trustDomainID] = bundle
		}
	}
	return &Update{
		Entries: regEntries,
		SVIDs:   svids,
		Bundles: bundles,
	}, nil
}

func (c *client) FetchJWTSVID(ctx context.Context, jsr *node.JSR, entryID string) (*JWTSVID, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	c.c.RotMtx.RLock()
	defer c.c.RotMtx.RUnlock()

	if c.c.ExperimentalAPIEnabled {
		return c.fetchJWTSVID(ctx, jsr, entryID)
	}

	nodeClient, nodeConn, err := c.newNodeClient(ctx)
	if err != nil {
		return nil, err
	}
	defer nodeConn.Release()

	response, err := nodeClient.FetchJWTSVID(ctx, &node.FetchJWTSVIDRequest{
		Jsr: jsr,
	})
	// We weren't able to make the request...close the client and return the error.
	if err != nil {
		c.release(nodeConn)
		c.c.Log.WithError(err).Errorf("Failure fetching JWT SVID. %v", ErrUnableToGetStream)
		return nil, ErrUnableToGetStream
	}

	svid := response.GetSvid()
	if svid == nil {
		return nil, errors.New("JWTSVID response missing SVID")
	}
	if svid.IssuedAt == 0 {
		return nil, errors.New("JWTSVID missing issued at")
	}
	if svid.ExpiresAt == 0 {
		return nil, errors.New("JWTSVID missing expires at")
	}
	if svid.IssuedAt > svid.ExpiresAt {
		return nil, errors.New("JWTSVID issued after it has expired")
	}

	return &JWTSVID{
		Token:     svid.Token,
		IssuedAt:  time.Unix(svid.IssuedAt, 0).UTC(),
		ExpiresAt: time.Unix(svid.ExpiresAt, 0).UTC(),
	}, nil
}

// Release the underlying connection.
func (c *client) Release() {
	c.release(nil)
}

func (c *client) release(conn *nodeConn) {
	c.m.Lock()
	defer c.m.Unlock()
	if c.connections != nil && (conn == nil || conn == c.connections) {
		c.connections.Release()
		c.connections = nil
	}
}

func (c *client) newNodeClient(ctx context.Context) (node.NodeClient, *nodeConn, error) {
	c.m.Lock()
	defer c.m.Unlock()

	// open a new connection
	if c.connections == nil {
		conn, err := c.dial(ctx)
		if err != nil {
			return nil, nil, err
		}
		c.connections = newNodeConn(conn)
	}
	c.connections.AddRef()
	return c.createNewNodeClient(c.connections.conn), c.connections, nil
}

func (c *client) dial(ctx context.Context) (*grpc.ClientConn, error) {
	return DialServer(ctx, DialServerConfig{
		Address:     c.c.Addr,
		TrustDomain: c.c.TrustDomain.Host,
		GetBundle: func() []*x509.Certificate {
			_, _, bundle := c.c.KeysAndBundle()
			return bundle
		},
		GetAgentCertificate: func() *tls.Certificate {
			chain, key, _ := c.c.KeysAndBundle()
			agentCert := &tls.Certificate{
				PrivateKey: key,
			}
			for _, cert := range chain {
				agentCert.Certificate = append(agentCert.Certificate, cert.Raw)
			}
			return agentCert
		},
		dialContext: c.dialContext,
	})
}

// validateRegistrationEntry validates required fields on registration entries.
// In order for a registration entry to be meaningful to the agent, it must
// have the following:
// - an entry id
// - a spiffe id
// - one or more selectors
func validateRegistrationEntry(entry *common.RegistrationEntry) error {
	switch {
	case entry.EntryId == "":
		return errors.New("missing entry ID")
	case entry.SpiffeId == "":
		return errors.New("missing SPIFFE ID")
	case len(entry.Selectors) == 0:
		return errors.New("no selectors")
	}
	return nil
}
