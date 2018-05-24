package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
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

var (
	ErrPartialResponse   = errors.New("partial response received")
	ErrUnableToGetStream = errors.New("unable to get a stream")
)

type Client interface {
	FetchUpdates(req *node.FetchSVIDRequest) (*Update, error)

	// Release releases any resources that were held by this Client, if any.
	Release()
}

// Config holds a client configuration
type Config struct {
	Addr        net.Addr
	Log         logrus.FieldLogger
	TrustDomain url.URL
	// KeysAndBundle is a callback that must return the keys and bundle used by the client
	// to connect via mTLS to Addr.
	KeysAndBundle func() (*x509.Certificate, *ecdsa.PrivateKey, []*x509.Certificate)
}

type Update struct {
	Entries map[string]*common.RegistrationEntry
	SVIDs   map[string]*node.Svid
	Bundle  []byte
}

type client struct {
	c          *Config
	conn       *grpc.ClientConn
	nodeClient node.NodeClient
	m          sync.Mutex
}

// New creates a new client struct with the configuration provided
func New(c *Config) *client {
	return &client{
		c: c,
	}
}

func newGRPCConn(c *Config) (*grpc.ClientConn, error) {
	credFunc := func() (credentials.TransportCredentials, error) {
		var tlsCert []tls.Certificate
		var tlsConfig *tls.Config

		svid, key, bundle := c.KeysAndBundle()
		spiffePeer := &spiffe_tls.TLSPeer{
			SpiffeIDs:  []string{"spiffe://" + c.TrustDomain.Host + "/spiffe/server"},
			TrustRoots: bundleAsCertPool(bundle),
		}
		tlsCert = append(tlsCert, tls.Certificate{Certificate: [][]byte{svid.Raw}, PrivateKey: key})
		tlsConfig = spiffePeer.NewTLSConfig(tlsCert)
		return credentials.NewTLS(tlsConfig), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // TODO: Make this timeout configurable?
	defer cancel()

	config := grpcutil.GRPCDialerConfig{
		Log:      grpcutil.LoggerFromFieldLogger(c.Log),
		CredFunc: credFunc,
	}
	dialer := grpcutil.NewGRPCDialer(config)
	conn, err := dialer.Dial(ctx, c.Addr)
	if err != nil {
		return nil, fmt.Errorf("cannot create connection: %v", err)
	}
	return conn, nil
}

func (c *client) FetchUpdates(req *node.FetchSVIDRequest) (*Update, error) {
	nodeClient, err := c.getNodeClient()
	if err != nil {
		return nil, err
	}

	stream, err := nodeClient.FetchSVID(context.Background())
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
				return &Update{regEntries, svids, lastBundle}, ErrPartialResponse
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
	return &Update{regEntries, svids, lastBundle}, nil
}

func (c *client) Release() {
	c.m.Lock()
	defer c.m.Unlock()

	if c.conn != nil {
		c.nodeClient = nil
		c.conn.Close()
		c.conn = nil
	}
}

func (c *client) getNodeClient() (node.NodeClient, error) {
	c.m.Lock()
	defer c.m.Unlock()

	if c.conn == nil {
		conn, err := newGRPCConn(c.c)
		if err != nil {
			return nil, err
		}
		c.conn = conn
		c.nodeClient = node.NewNodeClient(conn)
	}
	return c.nodeClient, nil
}

func (u *Update) String() string {
	var buffer bytes.Buffer
	buffer.WriteString("{ Entries: [")
	for _, re := range u.Entries {
		buffer.WriteString("{ spiffeID: ")
		buffer.WriteString(re.SpiffeId)
		buffer.WriteString(", parentID: ")
		buffer.WriteString(re.ParentId)
		buffer.WriteString(", selectors: ")
		buffer.WriteString(fmt.Sprintf("%v", re.Selectors))
		buffer.WriteString("}")
	}
	buffer.WriteString("], SVIDs: [")
	for key, svid := range u.SVIDs {
		buffer.WriteString(key)
		buffer.WriteString(": ")
		svidStr := svid.String()
		if len(svidStr) < 30 {
			buffer.WriteString(svidStr)
		} else {
			buffer.WriteString(svidStr[:30])
		}
		buffer.WriteString(" ")
	}
	buffer.WriteString("], Bundle: ")
	if u.Bundle != nil && len(u.Bundle) > 0 {
		buffer.WriteString("bytes")
	} else {
		buffer.WriteString("none")
	}
	buffer.WriteString("}")
	return buffer.String()
}

func bundleAsCertPool(bundle []*x509.Certificate) *x509.CertPool {
	certPool := x509.NewCertPool()
	for _, cert := range bundle {
		certPool.AddCert(cert)
	}
	return certPool
}
