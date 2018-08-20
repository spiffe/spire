package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	spiffe_tls "github.com/spiffe/go-spiffe/tls"
	"github.com/spiffe/spire/pkg/common/grpcutil"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	ErrUnableToGetStream = errors.New("unable to get a stream")
)

type JWTSVID struct {
	Token     string
	ExpiresAt time.Time
}

type Client interface {
	FetchUpdates(ctx context.Context, req *node.FetchX509SVIDRequest) (*Update, error)
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
	KeysAndBundle func() (*x509.Certificate, *ecdsa.PrivateKey, []*x509.Certificate)
}

type client struct {
	c    *Config
	conn *grpc.ClientConn
	m    sync.Mutex
	// Callback to be used for testing purposes.
	newNodeClientCallback func() (node.NodeClient, error)
}

// New creates a new client struct with the configuration provided
func New(c *Config) *client {
	return &client{
		c: c,
	}
}

func (c *client) credsFunc() (credentials.TransportCredentials, error) {
	var tlsCert []tls.Certificate
	var tlsConfig *tls.Config

	svid, key, bundle := c.c.KeysAndBundle()
	spiffePeer := &spiffe_tls.TLSPeer{
		SpiffeIDs:  []string{"spiffe://" + c.c.TrustDomain.Host + "/spire/server"},
		TrustRoots: util.NewCertPool(bundle...),
	}
	tlsCert = append(tlsCert, tls.Certificate{Certificate: [][]byte{svid.Raw}, PrivateKey: key})
	tlsConfig = spiffePeer.NewTLSConfig(tlsCert)
	return credentials.NewTLS(tlsConfig), nil
}

func (c *client) dial(ctx context.Context) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second) // TODO: Make this timeout configurable?
	defer cancel()

	config := grpcutil.GRPCDialerConfig{
		Log:      grpcutil.LoggerFromFieldLogger(c.c.Log),
		CredFunc: c.credsFunc,
	}
	dialer := grpcutil.NewGRPCDialer(config)
	conn, err := dialer.Dial(ctx, c.c.Addr)
	if err != nil {
		return nil, fmt.Errorf("cannot create connection: %v", err)
	}
	return conn, nil
}

func (c *client) FetchUpdates(ctx context.Context, req *node.FetchX509SVIDRequest) (*Update, error) {
	nodeClient, err := c.newNodeClient(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := nodeClient.FetchX509SVID(ctx)
	// We weren't able to get a stream...close the client and return the error.
	if err != nil {
		c.Release()
		c.c.Log.Errorf("%v: %v", ErrUnableToGetStream, err)
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
	svids := map[string]*node.X509SVID{}
	var lastBundle []byte
	// Read all the server responses from the stream.
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			// There was an error receiving a response, exit loop to return what we have.
			return &Update{regEntries, svids, lastBundle}, err
		}

		for _, re := range resp.SvidUpdate.RegistrationEntries {
			regEntries[re.EntryId] = re
		}
		for spiffeid, svid := range resp.SvidUpdate.Svids {
			svids[spiffeid] = svid
		}
		lastBundle = resp.SvidUpdate.Bundle
	}
	return &Update{
		Entries: regEntries,
		SVIDs:   svids,
		Bundle:  lastBundle,
	}, nil
}

func (c *client) FetchJWTSVID(ctx context.Context, jsr *node.JSR) (*JWTSVID, error) {
	nodeClient, err := c.newNodeClient(ctx)
	if err != nil {
		return nil, err
	}

	response, err := nodeClient.FetchJWTSVID(ctx, &node.FetchJWTSVIDRequest{
		Jsr: jsr,
	})
	// We weren't able to make the request...close the client and return the error.
	if err != nil {
		c.Release()
		c.c.Log.Errorf("%v: %v", ErrUnableToGetStream, err)
		return nil, ErrUnableToGetStream
	}

	svid := response.GetSvid()
	if svid == nil {
		return nil, errors.New("JWTSVID response missing SVID")
	}

	return &JWTSVID{
		Token:     svid.Token,
		ExpiresAt: time.Unix(svid.ExpiresAt, 0),
	}, nil
}

func (c *client) Release() {
	c.m.Lock()
	defer c.m.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

func (c *client) newNodeClient(ctx context.Context) (node.NodeClient, error) {
	if c.newNodeClientCallback != nil {
		return c.newNodeClientCallback()
	}

	c.m.Lock()
	defer c.m.Unlock()

	if c.conn == nil {
		conn, err := c.dial(ctx)
		if err != nil {
			return nil, err
		}
		c.conn = conn
	}
	return node.NewNodeClient(c.conn), nil
}
