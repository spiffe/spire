package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/api/node"
	agentpb "github.com/spiffe/spire/proto/spire/api/server/agent/v1"
	bundlepb "github.com/spiffe/spire/proto/spire/api/server/bundle/v1"
	entrypb "github.com/spiffe/spire/proto/spire/api/server/entry/v1"
	svidpb "github.com/spiffe/spire/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	FetchUpdates(ctx context.Context) (*Update, error)
	RenewSVID(ctx context.Context, csr []byte) (*node.X509SVID, error)
	NewX509SVIDs(ctx context.Context, csrs map[string][]byte) (map[string]*node.X509SVID, error)
	NewJWTSVID(ctx context.Context, jsr *node.JSR, entryID string) (*JWTSVID, error)

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
}

type client struct {
	c           *Config
	connections *nodeConn
	m           sync.Mutex

	// Constructor used for testing purposes.
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
		createNewEntryClient:  entrypb.NewEntryClient,
		createNewBundleClient: bundlepb.NewBundleClient,
		createNewSVIDClient:   svidpb.NewSVIDClient,
		createNewAgentClient:  agentpb.NewAgentClient,
	}
}

func (c *client) FetchUpdates(ctx context.Context) (*Update, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	c.c.RotMtx.RLock()
	defer c.c.RotMtx.RUnlock()

	protoEntries, err := c.fetchEntries(ctx)
	if err != nil {
		return nil, err
	}

	regEntries := make(map[string]*common.RegistrationEntry)
	federatesWith := make(map[string]bool)
	for _, e := range protoEntries {
		entry, err := slicedEntryFromProto(e)
		if err != nil {
			c.c.Log.WithFields(logrus.Fields{
				telemetry.RegistrationID: e.Id,
				telemetry.SPIFFEID:       e.SpiffeId,
				telemetry.Selectors:      e.Selectors,
				telemetry.Error:          err.Error(),
			}).Warn("Received malformed entry from SPIRE server")
			continue
		}

		// Get all federated trust domains
		for _, td := range entry.FederatesWith {
			federatesWith[td] = true
		}
		regEntries[entry.EntryId] = entry
	}

	keys := make([]string, 0, len(federatesWith))
	for key := range federatesWith {
		keys = append(keys, key)
	}

	protoBundles, err := c.fetchBundles(ctx, keys)
	if err != nil {
		return nil, err
	}

	bundles := make(map[string]*common.Bundle)
	for _, b := range protoBundles {
		bundle, err := bundleutil.CommonBundleFromProto(b)
		if err != nil {
			c.c.Log.WithError(err).Warn("Received malformed bundle from SPIRE server")
			continue
		}
		bundles[bundle.TrustDomainId] = bundle
	}

	return &Update{
		Entries: regEntries,
		Bundles: bundles,
	}, nil
}

func (c *client) RenewSVID(ctx context.Context, csr []byte) (*node.X509SVID, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	agentClient, connection, err := c.newAgentClient(ctx)
	if err != nil {
		return nil, err
	}
	defer connection.Release()

	resp, err := agentClient.RenewAgent(ctx, &agentpb.RenewAgentRequest{
		Params: &agentpb.AgentX509SVIDParams{
			Csr: csr,
		},
	})
	if err != nil {
		c.release(connection)
		c.c.Log.WithError(err).Error("Failed to renew agent")
		return nil, fmt.Errorf("failed to renew agent: %w", err)
	}

	var certChain []byte
	for _, cert := range resp.Svid.CertChain {
		certChain = append(certChain, cert...)
	}
	return &node.X509SVID{
		CertChain: certChain,
		ExpiresAt: resp.Svid.ExpiresAt,
	}, nil
}

func (c *client) NewX509SVIDs(ctx context.Context, csrs map[string][]byte) (map[string]*node.X509SVID, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	c.c.RotMtx.RLock()
	defer c.c.RotMtx.RUnlock()

	svids := make(map[string]*node.X509SVID)
	var params []*svidpb.NewX509SVIDParams
	for entryID, csr := range csrs {
		params = append(params, &svidpb.NewX509SVIDParams{
			EntryId: entryID,
			Csr:     csr,
		})
	}

	protoSVIDs, err := c.fetchSVIDs(ctx, params)
	if err != nil {
		return nil, err
	}

	for i, s := range protoSVIDs {
		entryID := params[i].EntryId
		if s == nil {
			c.c.Log.WithField(telemetry.RegistrationID, entryID).Debug("Entry not found")
			continue
		}
		var certChain []byte
		for _, cert := range s.CertChain {
			certChain = append(certChain, cert...)
		}

		svids[entryID] = &node.X509SVID{
			CertChain: certChain,
			ExpiresAt: s.ExpiresAt,
		}
	}

	return svids, nil
}

func (c *client) NewJWTSVID(ctx context.Context, jsr *node.JSR, entryID string) (*JWTSVID, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	c.c.RotMtx.RLock()
	defer c.c.RotMtx.RUnlock()

	svidClient, connection, err := c.newSVIDClient(ctx)
	if err != nil {
		return nil, err
	}
	defer connection.Release()

	resp, err := svidClient.NewJWTSVID(ctx, &svidpb.NewJWTSVIDRequest{
		Audience: jsr.Audience,
		EntryId:  entryID,
	})
	if err != nil {
		c.release(connection)
		c.c.Log.WithError(err).Error("Failed to fetch JWT SVID")
		return nil, fmt.Errorf("failed to fetch JWT SVID: %w", err)
	}

	svid := resp.Svid
	switch {
	case svid == nil:
		return nil, errors.New("JWTSVID response missing SVID")
	case svid.IssuedAt == 0:
		return nil, errors.New("JWTSVID missing issued at")
	case svid.ExpiresAt == 0:
		return nil, errors.New("JWTSVID missing expires at")
	case svid.IssuedAt > svid.ExpiresAt:
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

func (c *client) fetchEntries(ctx context.Context) ([]*types.Entry, error) {
	entryClient, connection, err := c.newEntryClient(ctx)
	if err != nil {
		return nil, err
	}
	defer connection.Release()

	resp, err := entryClient.GetAuthorizedEntries(ctx, &entrypb.GetAuthorizedEntriesRequest{})
	if err != nil {
		c.release(connection)
		c.c.Log.WithError(err).Error("Failed to fetch authorized entries")
		return nil, fmt.Errorf("failed to fetch authorized entries: %w", err)
	}

	return resp.Entries, err
}

func (c *client) fetchBundles(ctx context.Context, federatedBundles []string) ([]*types.Bundle, error) {
	bundleClient, connection, err := c.newBundleClient(ctx)
	if err != nil {
		return nil, err
	}
	defer connection.Release()

	var bundles []*types.Bundle

	// Get bundle
	bundle, err := bundleClient.GetBundle(ctx, &bundlepb.GetBundleRequest{})
	if err != nil {
		c.release(connection)
		c.c.Log.WithError(err).Error("Failed to fetch bundle")
		return nil, fmt.Errorf("failed to fetch bundle: %w", err)
	}
	bundles = append(bundles, bundle)

	for _, b := range federatedBundles {
		federatedTD, err := spiffeid.TrustDomainFromString(b)
		if err != nil {
			return nil, err
		}
		bundle, err := bundleClient.GetFederatedBundle(ctx, &bundlepb.GetFederatedBundleRequest{
			TrustDomain: federatedTD.String(),
		})
		switch status.Code(err) {
		case codes.OK:
			bundles = append(bundles, bundle)
		case codes.NotFound:
			c.c.Log.WithError(err).WithField(telemetry.FederatedBundle, b).Warn("Federated bundle not found")
		default:
			c.c.Log.WithError(err).WithField(telemetry.FederatedBundle, b).Error("Failed to fetch federated bundle")
			return nil, fmt.Errorf("failed to fetch federated bundle: %w", err)
		}
	}

	return bundles, nil
}

func (c *client) fetchSVIDs(ctx context.Context, params []*svidpb.NewX509SVIDParams) ([]*types.X509SVID, error) {
	svidClient, connection, err := c.newSVIDClient(ctx)
	if err != nil {
		return nil, err
	}
	defer connection.Release()

	resp, err := svidClient.BatchNewX509SVID(ctx, &svidpb.BatchNewX509SVIDRequest{
		Params: params,
	})
	if err != nil {
		c.release(connection)
		c.c.Log.WithError(err).Error("Failed to batch new X509 SVID(s)")
		return nil, fmt.Errorf("failed to batch new X509 SVID(s): %w", err)
	}

	okStatus := int32(codes.OK)
	var svids []*types.X509SVID
	for i, r := range resp.Results {
		if r.Status.Code != okStatus {
			c.c.Log.WithFields(logrus.Fields{
				telemetry.RegistrationID: params[i].EntryId,
				telemetry.Status:         r.Status.Code,
				telemetry.Error:          r.Status.Message,
			}).Warn("Failed to mint X509 SVID")
		}

		svids = append(svids, r.Svid)
	}

	return svids, nil
}

func (c *client) newEntryClient(ctx context.Context) (entrypb.EntryClient, *nodeConn, error) {
	c.m.Lock()
	defer c.m.Unlock()

	if c.connections == nil {
		conn, err := c.dial(ctx)
		if err != nil {
			return nil, nil, err
		}
		c.connections = newNodeConn(conn)
	}

	c.connections.AddRef()
	return c.createNewEntryClient(c.connections.conn), c.connections, nil
}

func (c *client) newBundleClient(ctx context.Context) (bundlepb.BundleClient, *nodeConn, error) {
	c.m.Lock()
	defer c.m.Unlock()

	if c.connections == nil {
		conn, err := c.dial(ctx)
		if err != nil {
			return nil, nil, err
		}
		c.connections = newNodeConn(conn)
	}
	c.connections.AddRef()
	return c.createNewBundleClient(c.connections.conn), c.connections, nil
}

func (c *client) newSVIDClient(ctx context.Context) (svidpb.SVIDClient, *nodeConn, error) {
	c.m.Lock()
	defer c.m.Unlock()

	if c.connections == nil {
		conn, err := c.dial(ctx)
		if err != nil {
			return nil, nil, err
		}
		c.connections = newNodeConn(conn)
	}
	c.connections.AddRef()
	return c.createNewSVIDClient(c.connections.conn), c.connections, nil
}

func (c *client) newAgentClient(ctx context.Context) (agentpb.AgentClient, *nodeConn, error) {
	c.m.Lock()
	defer c.m.Unlock()

	if c.connections == nil {
		conn, err := c.dial(ctx)
		if err != nil {
			return nil, nil, err
		}
		c.connections = newNodeConn(conn)
	}
	c.connections.AddRef()
	return c.createNewAgentClient(c.connections.conn), c.connections, nil
}
