package ca

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// BundleUpdater is the interface used by the UpstreamClient to append bundle
// updates.
type BundleUpdater interface {
	SyncX509Roots(ctx context.Context, roots []*x509certificate.X509Authority) error
	AppendJWTKeys(ctx context.Context, keys []*common.PublicKey) ([]*common.PublicKey, error)
	LogError(err error, msg string)
}

// ValidateX509CAFunc is used by the upstream client to validate an X509CA
// newly minted by an upstream authority before it accepts it.
type ValidateX509CAFunc = func(x509CA, x509Roots []*x509.Certificate) error

// UpstreamClientConfig is the configuration for an UpstreamClient. Each field
// is required.
type UpstreamClientConfig struct {
	UpstreamAuthority upstreamauthority.UpstreamAuthority
	BundleUpdater     BundleUpdater
}

// UpstreamClient is used to interact with and stream updates from the
// UpstreamAuthority plugin.
type UpstreamClient struct {
	c UpstreamClientConfig

	mintX509CAMtx       sync.Mutex
	mintX509CAStream    *streamState
	publishJWTKeyMtx    sync.Mutex
	publishJWTKeyStream *streamState
}

// NewUpstreamClient returns a new UpstreamAuthority plugin client.
func NewUpstreamClient(config UpstreamClientConfig) *UpstreamClient {
	return &UpstreamClient{
		c:                   config,
		mintX509CAStream:    newStreamState(),
		publishJWTKeyStream: newStreamState(),
	}
}

// Close closes the client, stopping any open streams against the
// UpstreamAuthority plugin.
func (u *UpstreamClient) Close() error {
	func() {
		u.mintX509CAMtx.Lock()
		defer u.mintX509CAMtx.Unlock()
		u.mintX509CAStream.Stop()
	}()
	func() {
		u.publishJWTKeyMtx.Lock()
		defer u.publishJWTKeyMtx.Unlock()
		u.publishJWTKeyStream.Stop()
	}()
	return nil
}

// MintX509CA mints an X.509CA using the UpstreamAuthority. It maintains an
// open stream to the UpstreamAuthority plugin to receive and append X.509 root
// updates to the bundle. The stream remains open until another call to
// MintX509CA happens or the client is closed.
func (u *UpstreamClient) MintX509CA(ctx context.Context, csr []byte, ttl time.Duration, validateX509CA ValidateX509CAFunc) (_ []*x509.Certificate, err error) {
	u.mintX509CAMtx.Lock()
	defer u.mintX509CAMtx.Unlock()

	firstResultCh := make(chan mintX509CAResult, 1)
	u.mintX509CAStream.Start(func(streamCtx context.Context) {
		u.runMintX509CAStream(streamCtx, csr, ttl, validateX509CA, firstResultCh)
	})
	defer func() {
		if err != nil {
			u.mintX509CAStream.Stop()
		}
	}()

	select {
	case result := <-firstResultCh:
		return result.x509CA, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// WaitUntilMintX509CAStreamDone waits until the MintX509CA stream has stopped.
func (u *UpstreamClient) WaitUntilMintX509CAStreamDone(ctx context.Context) error {
	return u.mintX509CAStream.WaitUntilStopped(ctx)
}

// PublishJWTKey publishes the JWT key to the UpstreamAuthority. It maintains
// an open stream to the UpstreamAuthority plugin to receive and append JWT key
// updates to the bundle. The stream remains open until another call to
// PublishJWTKey happens or the client is closed.
func (u *UpstreamClient) PublishJWTKey(ctx context.Context, jwtKey *common.PublicKey) (_ []*common.PublicKey, err error) {
	u.publishJWTKeyMtx.Lock()
	defer u.publishJWTKeyMtx.Unlock()

	firstResultCh := make(chan publishJWTKeyResult, 1)
	u.publishJWTKeyStream.Start(func(streamCtx context.Context) {
		u.runPublishJWTKeyStream(streamCtx, jwtKey, firstResultCh)
	})
	defer func() {
		if err != nil {
			u.publishJWTKeyStream.Stop()
		}
	}()

	select {
	case result := <-firstResultCh:
		return result.jwtKeys, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// WaitUntilPublishJWTKeyStreamDone waits until the MintX509CA stream has stopped.
func (u *UpstreamClient) WaitUntilPublishJWTKeyStreamDone(ctx context.Context) error {
	return u.publishJWTKeyStream.WaitUntilStopped(ctx)
}

func (u *UpstreamClient) runMintX509CAStream(ctx context.Context, csr []byte, ttl time.Duration, validateX509CA ValidateX509CAFunc, firstResultCh chan<- mintX509CAResult) {
	x509CA, x509Roots, x509RootsStream, err := u.c.UpstreamAuthority.MintX509CA(ctx, csr, ttl)
	if err != nil {
		firstResultCh <- mintX509CAResult{err: err}
		return
	}
	defer x509RootsStream.Close()

	// Extract all root certificates
	var x509RootCerts []*x509.Certificate
	for _, eachRoot := range x509Roots {
		x509RootCerts = append(x509RootCerts, eachRoot.Certificate)
	}

	// Before we append the roots and return the response, we must first
	// validate that the minted intermediate can sign a valid, conformant
	// X509-SVID chain of trust using the provided callback.
	if err := validateX509CA(x509CA, x509RootCerts); err != nil {
		err = status.Errorf(codes.InvalidArgument, "X509 CA minted by upstream authority is invalid: %v", err)
		firstResultCh <- mintX509CAResult{err: err}
		return
	}

	if err := u.c.BundleUpdater.SyncX509Roots(ctx, x509Roots); err != nil {
		firstResultCh <- mintX509CAResult{err: err}
		return
	}

	firstResultCh <- mintX509CAResult{x509CA: x509CA}

	for {
		x509Roots, err := x509RootsStream.RecvUpstreamX509Authorities()
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				// This is normal if the plugin does not support streaming
				// bundle updates.
			case status.Code(err) == codes.Canceled:
				// This is normal. This client cancels this stream when opening
				// a new stream.
			default:
				u.c.BundleUpdater.LogError(err, "The upstream authority plugin stopped streaming X.509 root updates prematurely. Please report this bug. Will retry later.")
			}
			return
		}

		if err := u.c.BundleUpdater.SyncX509Roots(ctx, x509Roots); err != nil {
			u.c.BundleUpdater.LogError(err, "Failed to store X.509 roots received by the upstream authority plugin.")
			continue
		}
	}
}

func (u *UpstreamClient) runPublishJWTKeyStream(ctx context.Context, jwtKey *common.PublicKey, firstResultCh chan<- publishJWTKeyResult) {
	jwtKeys, jwtKeysStream, err := u.c.UpstreamAuthority.PublishJWTKey(ctx, jwtKey)
	if err != nil {
		firstResultCh <- publishJWTKeyResult{err: err}
		return
	}
	defer jwtKeysStream.Close()

	updatedKeys, err := u.c.BundleUpdater.AppendJWTKeys(ctx, jwtKeys)
	if err != nil {
		firstResultCh <- publishJWTKeyResult{err: err}
		return
	}
	firstResultCh <- publishJWTKeyResult{jwtKeys: updatedKeys}

	for {
		jwtKeys, err := jwtKeysStream.RecvUpstreamJWTAuthorities()
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				// This is normal if the plugin does not support streaming
				// bundle updates.
			case status.Code(err) == codes.Canceled:
				// This is normal. This client cancels this stream when opening
				// a new stream.
			default:
				u.c.BundleUpdater.LogError(err, "The upstream authority plugin stopped streaming JWT key updates prematurely. Please report this bug. Will retry later.")
			}
			return
		}

		if _, err := u.c.BundleUpdater.AppendJWTKeys(ctx, jwtKeys); err != nil {
			u.c.BundleUpdater.LogError(err, "Failed to store JWT keys received by the upstream authority plugin.")
			continue
		}
	}
}

type mintX509CAResult struct {
	x509CA []*x509.Certificate
	err    error
}

type publishJWTKeyResult struct {
	jwtKeys []*common.PublicKey
	err     error
}

// streamState manages the state for open streams to the plugin that are
// receiving bundle updates. It is protected by the respective mutexes in
// the UpstreamClient.
type streamState struct {
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	stopOnce *sync.Once
	stopped  chan struct{}
}

func newStreamState() *streamState {
	return &streamState{
		cancel:   func() {},
		stopOnce: new(sync.Once),
		stopped:  make(chan struct{}),
	}
}

func (s *streamState) Stop() {
	s.stopOnce.Do(s.stop)
}

func (s *streamState) Start(fn func(context.Context)) {
	s.Stop()

	s.stopOnce = new(sync.Once)
	s.stopped = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		fn(ctx)
	}()
}

func (s *streamState) WaitUntilStopped(ctx context.Context) error {
	select {
	case <-s.stopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *streamState) stop() {
	s.cancel()
	s.wg.Wait()
	close(s.stopped)
}
