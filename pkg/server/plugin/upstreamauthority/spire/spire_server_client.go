package spireplugin

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// newServerClient creates a new spire-sever client
func newServerClient(serverID spiffeid.ID, serverAddr string, workloadapiSocket string) *serverClient {
	return &serverClient{
		serverID:          serverID,
		serverAddr:        serverAddr,
		workloadAPISocket: workloadapiSocket,
	}
}

type serverClient struct {
	serverID          spiffeid.ID
	conn              *grpc.ClientConn
	serverAddr        string
	workloadAPISocket string

	mtx    sync.RWMutex
	source *workloadapi.X509Source

	bundleClient bundle.BundleClient
	svidClient   svid.SVIDClient
}

// start initializes spire-server endpoints client, it uses X509 source to keep an active connection
func (c *serverClient) start(ctx context.Context) error {
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(c.workloadAPISocket)))
	if err != nil {
		return fmt.Errorf("unable to create X509Source: %v", err)
	}

	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(c.serverID))
	conn, err := grpc.DialContext(ctx, c.serverAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		source.Close()
		return fmt.Errorf("error dialing: %v", err)
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()
	// Close active connection
	if c.conn != nil {
		c.conn.Close()
	}
	// Update connection and source
	c.conn = conn
	c.source = source
	c.bundleClient = bundle.NewBundleClient(c.conn)
	c.svidClient = svid.NewSVIDClient(c.conn)

	return nil
}

// release releases the connection to SPIRE server and cleans clients
func (c *serverClient) release() {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c.conn != nil {
		c.conn.Close()
	}
	if c.source != nil {
		c.source.Close()
	}
	c.conn = nil
	c.source = nil
	c.bundleClient = nil
	c.svidClient = nil
}

// newDownstreamX509CA requests new downstream CAs to server
func (c *serverClient) newDownstreamX509CA(ctx context.Context, csr []byte) ([]*x509.Certificate, []*x509.Certificate, error) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	resp, err := c.svidClient.NewDownstreamX509CA(ctx, &svid.NewDownstreamX509CARequest{
		Csr: csr,
	})
	if err != nil {
		return nil, nil, err
	}

	// parse authorities to verify that are valid X509 certificates
	bundles, err := x509util.RawCertsToCertificates(resp.X509Authorities)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse X509 authorities: %v", err)
	}

	// parse cert chains to verify that are valid X509 certificates
	certs, err := x509util.RawCertsToCertificates(resp.CaCertChain)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse CA cert chain: %v", err)
	}

	return certs, bundles, nil
}

// newDownstreamX509CA publishes a JWT key to the server
func (c *serverClient) publishJWTAuthority(ctx context.Context, key *common.PublicKey) ([]*types.JWTKey, error) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	resp, err := c.bundleClient.PublishJWTAuthority(ctx, &bundle.PublishJWTAuthorityRequest{
		JwtAuthority: &types.JWTKey{
			PublicKey: key.PkixBytes,
			ExpiresAt: key.NotAfter,
			KeyId:     key.Kid,
		},
	})
	if err != nil {
		return nil, err
	}

	return resp.JwtAuthorities, nil
}

// getBundle gets the bundle for the trust domain of the server
func (c *serverClient) getBundle(ctx context.Context) (*types.Bundle, error) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	bundle, err := c.bundleClient.GetBundle(ctx, &bundle.GetBundleRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to get bundle: %v", err)
	}

	return bundle, nil
}
