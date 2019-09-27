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
	"github.com/spiffe/spire/proto/spire/api/node"
	"github.com/spiffe/spire/proto/spire/common"

	"google.golang.org/grpc"
)

var (
	ErrUnableToGetStream = errors.New("unable to get a stream")
)

type JWTSVID struct {
	Token     string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type Client interface {
	FetchUpdates(ctx context.Context, req *node.FetchX509SVIDRequest, forRotation bool) (*Update, error)
	FetchJWTSVID(ctx context.Context, jsr *node.JSR) (*JWTSVID, error)

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
	c        *Config
	nodeConn *nodeConn
	m        sync.Mutex
	// Constructor to be used for testing purposes.
	createNewNodeClient func(*grpc.ClientConn) node.NodeClient
}

// New creates a new client struct with the configuration provided
func New(c *Config) *client {
	return &client{
		c:                   c,
		createNewNodeClient: node.NewNodeClient,
	}
}

func (c *client) FetchUpdates(ctx context.Context, req *node.FetchX509SVIDRequest, forRotation bool) (*Update, error) {
	if !forRotation {
		c.c.RotMtx.RLock()
		defer c.c.RotMtx.RUnlock()
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
	err = stream.Send(req)
	// Close the stream whether there was an error or not
	stream.CloseSend()
	if err != nil {
		c.release(nodeConn)
		return nil, err
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
			logrus.Errorf("failed to consume entire SVID update stream: %v", err)
			c.release(nodeConn)
			return nil, err
		}

		if resp.SvidUpdate == nil {
			logrus.Warn("empty update in SVID update stream")
			continue
		}

		for _, re := range resp.SvidUpdate.RegistrationEntries {
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

func (c *client) FetchJWTSVID(ctx context.Context, jsr *node.JSR) (*JWTSVID, error) {
	c.c.RotMtx.RLock()
	defer c.c.RotMtx.RUnlock()

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
	if c.nodeConn != nil && (conn == nil || conn == c.nodeConn) {
		c.nodeConn.Release()
		c.nodeConn = nil
	}
}

func (c *client) newNodeClient(ctx context.Context) (node.NodeClient, *nodeConn, error) {
	c.m.Lock()
	defer c.m.Unlock()

	// open a new connection
	if c.nodeConn == nil {
		conn, err := c.dial(ctx)
		if err != nil {
			return nil, nil, err
		}
		c.nodeConn = newNodeConn(conn)
	}
	c.nodeConn.AddRef()
	return c.createNewNodeClient(c.nodeConn.conn), c.nodeConn, nil
}

func (c *client) dial(ctx context.Context) (*grpc.ClientConn, error) {
	return DialServer(ctx, DialServerConfig{
		Log:         c.c.Log,
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
	})
}
