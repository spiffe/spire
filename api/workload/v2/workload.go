package workload

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	// DefaultAgentAddress is the default GRPC address to contact the spire agent at.
	DefaultAgentAddress = "unix:///tmp/agent.sock"

	// EnvVarAgentAddress is the environment variable name where the Workload API address may be configured.
	EnvVarAgentAddress = "SPIFFE_ENDPOINT_SOCKET"

	_unixPathPrefix = "unix://"
)

// X509SVIDs is an X.509 SVID response from the SPIFFE Workload API.
type X509SVIDs struct {
	// SVIDs is a list of X509SVID messages, each of which includes a single
	// SPIFFE Verifiable Identity Document, along with its private key and bundle.
	SVIDs []*X509SVID

	// CRL is a list of revoked certificates.
	// Unimplemented.
	CRL *pkix.CertificateList

	// FederatedBundles are CA certificate bundles belonging to foreign Trust Domains
	// that the workload should trust, keyed by the SPIFFE ID of the foreign domain.
	// Unimplemented.
	FederatedBundles map[string][]*x509.Certificate
}

// Default returns the default SVID (the first in the list).
//
// See the SPIFFE Workload API standard Section 5.3
// (https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE_Workload_API.md#53-default-identity)
func (x *X509SVIDs) Default() *X509SVID {
	return x.SVIDs[0]
}

// SVID is an X.509 SPIFFE Verifiable Identity Document.
//
// See https://github.com/spiffe/spiffe/blob/master/standards/X509-SVID.md
type X509SVID struct {
	SPIFFEID        string
	PrivateKey      crypto.Signer
	Certificates    []*x509.Certificate
	TrustBundle     []*x509.Certificate
	TrustBundlePool *x509.CertPool
}

// WorkloadX509SVIDWatcher is implemented by consumers who wish to be updated on SVID changes.
type WorkloadX509SVIDWatcher interface {
	// UpdateX509SVIDs indicates to the Watcher that the SVID has been updated
	UpdateX509SVIDs(*X509SVIDs)

	// OnError indicates an error occurred.
	OnError(err error)
}

// X509SVIDClient interacts with the SPIFFE Workload API.
type X509SVIDClient struct {
	watcher      WorkloadX509SVIDWatcher
	addr         string
	wg           sync.WaitGroup
	ctx          context.Context
	cancelFn     func()
	backoff      *backoff
	stateManager *clientStateManager
}

// Option configures the workload client.
type Option func(*X509SVIDClient)

// WithAddr specifies the unix socket address of the SPIFFE agent.
func WithAddr(addr string) Option {
	return func(w *X509SVIDClient) {
		w.addr = addr
	}
}

// NewX509SVIDClient returns a new Workload API client for X.509 SVIDs.
func NewX509SVIDClient(watcher WorkloadX509SVIDWatcher, opts ...Option) (*X509SVIDClient, error) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &X509SVIDClient{
		addr:         GetAgentAddress(),
		watcher:      watcher,
		ctx:          ctx,
		cancelFn:     cancel,
		backoff:      newBackoff(),
		stateManager: newClientStateManager(),
	}
	for _, opt := range opts {
		opt(c)
	}
	if !strings.HasPrefix(c.addr, _unixPathPrefix) {
		return nil, fmt.Errorf("spiffe/workload: agent address %q is not a unix address", c.addr)
	}
	return c, nil
}

// Start starts the client.
//
// The client will always start, and users should rely on the watcher
// interface to receives updates on the client's status.
//
// It is an error to call Start() more than once. Calling Start() after
// Stop() is not supported.
func (c *X509SVIDClient) Start(ctx context.Context) error {
	if err := c.stateManager.StartIfStartable(); err != nil {
		return fmt.Errorf("spiffe/workload: %v", err)
	}
	c.wg.Add(1)
	go c.run()
	return nil
}

func (c *X509SVIDClient) run() {
	defer c.wg.Done()

	conn := c.newConn()
	if conn == nil {
		return
	}
	defer conn.Close()

	for {
		if done := c.watch(conn); done {
			return
		}
	}
}

// establishes a new persistent connection, returns nil if a connection can't be created
func (c *X509SVIDClient) newConn() *grpc.ClientConn {
	for {
		conn, err := grpc.DialContext(c.ctx, c.addr, grpc.WithInsecure())
		if err != nil {
			if done := c.handleError(err); done {
				return nil
			}
			continue
		}
		c.backoff.Reset()
		return conn
	}
}

// handles an error, applies backoff, and returns true if the context has been canceled
func (c *X509SVIDClient) handleError(err error) (done bool) {
	if status.Code(err) == codes.Canceled {
		return true
	}
	c.watcher.OnError(err)
	select {
	case <-time.After(c.backoff.Duration()):
		return false
	case <-c.ctx.Done():
		return true
	}
}

// creates single watch for the connection and returns whether we should stop watching
func (c *X509SVIDClient) watch(conn *grpc.ClientConn) bool {
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	stream, err := c.newX509SVIDStream(ctx, conn)
	if err != nil {
		return c.handleError(err)
	}
	if err := c.handleX509SVIDStream(stream); err != nil {
		return c.handleError(err)
	}
	return false
}

func (c *X509SVIDClient) newX509SVIDStream(ctx context.Context, conn *grpc.ClientConn) (workload.SpiffeWorkloadAPI_FetchX509SVIDClient, error) {
	workloadClient := workload.NewSpiffeWorkloadAPIClient(conn)
	header := metadata.Pairs("workload.spiffe.io", "true")
	grpcCtx := metadata.NewOutgoingContext(ctx, header)
	return workloadClient.FetchX509SVID(grpcCtx, &workload.X509SVIDRequest{})
}

func (c *X509SVIDClient) handleX509SVIDStream(stream workload.SpiffeWorkloadAPI_FetchX509SVIDClient) error {
	for {
		resp, err := stream.Recv()
		if err != nil {
			return err
		}
		svids, err := protoToX509SVIDs(resp)
		if err != nil {
			c.watcher.OnError(err)
			continue
		}
		c.backoff.Reset()
		c.watcher.UpdateX509SVIDs(svids)
	}
}

// Stop stops the client and waits for the watch loop to end.
func (c *X509SVIDClient) Stop(ctx context.Context) error {
	if err := c.stateManager.StopIfStoppable(); err != nil {
		return fmt.Errorf("spiffe/workload: %v", err)
	}
	c.cancelFn()
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// GetAgentAddress returns the Workload API agent address configured by the environment or a default.
func GetAgentAddress() string {
	if addr := os.Getenv(EnvVarAgentAddress); addr != "" {
		return addr
	}
	return DefaultAgentAddress
}
