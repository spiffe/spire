package spireplugin

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/tlspolicy"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/common/x509util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// newServerClient creates a new spire-server client
func newServerClient(serverID spiffeid.ID, serverAddr string, workloadAPIAddr net.Addr, log hclog.Logger, tlsPolicy tlspolicy.Policy) *serverClient {
	return &serverClient{
		serverID:        serverID,
		serverAddr:      serverAddr,
		workloadAPIAddr: workloadAPIAddr,
		log:             &logAdapter{log: log},
		tlsPolicy:       tlsPolicy,
	}
}

type serverClient struct {
	serverID        spiffeid.ID
	conn            *grpc.ClientConn
	serverAddr      string
	workloadAPIAddr net.Addr
	log             logger.Logger
	tlsPolicy       tlspolicy.Policy

	mtx    sync.RWMutex
	source *workloadapi.X509Source

	bundleClient bundlev1.BundleClient
	svidClient   svidv1.SVIDClient
}

// start initializes spire-server endpoints client, it uses X509 source to keep an active connection
func (c *serverClient) start(ctx context.Context) error {
	clientOption, err := util.GetWorkloadAPIClientOption(c.workloadAPIAddr)
	if err != nil {
		return status.Errorf(codes.Internal, "could not get Workload API client options: %v", err)
	}
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(clientOption,
		workloadapi.WithLogger(c.log)))
	if err != nil {
		return status.Errorf(codes.Internal, "unable to create X509Source: %v", err)
	}

	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(c.serverID))
	err = tlspolicy.ApplyPolicy(tlsConfig, c.tlsPolicy)
	if err != nil {
		source.Close()
		return status.Errorf(codes.Internal, "error applying TLS policy: %v", err)
	}

	conn, err := grpc.NewClient(c.serverAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		source.Close()
		return status.Errorf(codes.Internal, "error dialing: %v", err)
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
	c.bundleClient = bundlev1.NewBundleClient(c.conn)
	c.svidClient = svidv1.NewSVIDClient(c.conn)

	return nil
}

// release releases the connection to SPIRE server and cleans clients
func (c *serverClient) release() {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	if c.source != nil {
		c.source.Close()
		c.source = nil
	}
	c.bundleClient = nil
	c.svidClient = nil
}

// newDownstreamX509CA requests new downstream CAs to server
func (c *serverClient) newDownstreamX509CA(ctx context.Context, csr []byte, preferredTTL int32) ([]*x509.Certificate, []*x509.Certificate, error) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	resp, err := c.svidClient.NewDownstreamX509CA(ctx, &svidv1.NewDownstreamX509CARequest{
		Csr:          csr,
		PreferredTtl: preferredTTL,
	})
	if err != nil {
		return nil, nil, err
	}

	// parse authorities to verify that are valid X509 certificates
	bundles, err := x509util.RawCertsToCertificates(resp.X509Authorities)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "unable to parse X509 authorities: %v", err)
	}

	// parse cert chains to verify that are valid X509 certificates
	certs, err := x509util.RawCertsToCertificates(resp.CaCertChain)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "unable to parse CA cert chain: %v", err)
	}

	return certs, bundles, nil
}

// newDownstreamX509CA publishes a JWT key to the server
func (c *serverClient) publishJWTAuthority(ctx context.Context, key *types.JWTKey) ([]*types.JWTKey, error) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	resp, err := c.bundleClient.PublishJWTAuthority(ctx, &bundlev1.PublishJWTAuthorityRequest{
		JwtAuthority: key,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to push JWT authority: %v", err)
	}

	return resp.JwtAuthorities, nil
}

// getBundle gets the bundle for the trust domain of the server
func (c *serverClient) getBundle(ctx context.Context) (*types.Bundle, error) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	bundle, err := c.bundleClient.GetBundle(ctx, &bundlev1.GetBundleRequest{})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get bundle: %v", err)
	}

	return bundle, nil
}

type logAdapter struct {
	log hclog.Logger
}

func (l *logAdapter) Debugf(format string, args ...any) {
	l.log.Debug(fmt.Sprintf(format, args...))
}

func (l *logAdapter) Infof(format string, args ...any) {
	l.log.Info(fmt.Sprintf(format, args...))
}

func (l *logAdapter) Warnf(format string, args ...any) {
	l.log.Warn(fmt.Sprintf(format, args...))
}

func (l *logAdapter) Errorf(format string, args ...any) {
	l.log.Error(fmt.Sprintf(format, args...))
}
