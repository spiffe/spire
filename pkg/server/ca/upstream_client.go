package ca

import (
	"context"
	"crypto/x509"
	"io"
	"sync"
	"time"

	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// BundleUpdater is the interface used by the UpstreamClient to append bundle
// updates.
type BundleUpdater interface {
	AppendX509Roots(ctx context.Context, roots []*x509.Certificate) error
	AppendJWTKeys(ctx context.Context, keys []*common.PublicKey) ([]*common.PublicKey, error)
	LogError(err error, msg string)
}

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
func (u *UpstreamClient) MintX509CA(ctx context.Context, csr []byte, ttl time.Duration) (_ []*x509.Certificate, err error) {
	u.mintX509CAMtx.Lock()
	defer u.mintX509CAMtx.Unlock()

	req := &upstreamauthority.MintX509CARequest{
		Csr:          csr,
		PreferredTtl: int32(ttl / time.Second),
	}

	firstResultCh := make(chan mintX509CAResult, 1)
	u.mintX509CAStream.Start(func(streamCtx context.Context) {
		u.runMintX509CAStream(streamCtx, req, firstResultCh)
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

	req := &upstreamauthority.PublishJWTKeyRequest{
		JwtKey: jwtKey,
	}

	firstResultCh := make(chan publishJWTKeyResult, 1)
	u.publishJWTKeyStream.Start(func(streamCtx context.Context) {
		u.runPublishJWTKeyStream(streamCtx, req, firstResultCh)
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

func (u *UpstreamClient) runMintX509CAStream(ctx context.Context, req *upstreamauthority.MintX509CARequest, firstResultCh chan<- mintX509CAResult) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := u.c.UpstreamAuthority.MintX509CA(ctx, req)
	if err != nil {
		firstResultCh <- mintX509CAResult{err: err}
		return
	}

	resp, err := stream.Recv()
	if err != nil {
		firstResultCh <- mintX509CAResult{err: err}
		return
	}

	x509CA, x509Roots, err := parseMintX509CAFirstResponse(resp)
	if err != nil {
		firstResultCh <- mintX509CAResult{err: err}
		return
	}

	if err := u.c.BundleUpdater.AppendX509Roots(ctx, x509Roots); err != nil {
		firstResultCh <- mintX509CAResult{err: err}
		return
	}

	firstResultCh <- mintX509CAResult{x509CA: x509CA}

	for {
		resp, err := stream.Recv()
		if err != nil {
			switch {
			case err == io.EOF:
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

		x509Roots, err := parseMintX509CABundleUpdate(resp)
		if err != nil {
			u.c.BundleUpdater.LogError(err, "Failed to parse an X.509 root update from the upstream authority plugin. Please report this bug.")
			continue
		}

		if err := u.c.BundleUpdater.AppendX509Roots(ctx, x509Roots); err != nil {
			u.c.BundleUpdater.LogError(err, "Failed to store X.509 roots received by the upstream authority plugin.")
			continue
		}
	}
}

func (u *UpstreamClient) runPublishJWTKeyStream(ctx context.Context, req *upstreamauthority.PublishJWTKeyRequest, firstResultCh chan<- publishJWTKeyResult) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := u.c.UpstreamAuthority.PublishJWTKey(ctx, req)
	if err != nil {
		firstResultCh <- publishJWTKeyResult{err: err}
		return
	}

	resp, err := stream.Recv()
	if err != nil {
		firstResultCh <- publishJWTKeyResult{err: err}
		return
	}

	updatedKeys, err := u.c.BundleUpdater.AppendJWTKeys(ctx, resp.UpstreamJwtKeys)
	if err != nil {
		firstResultCh <- publishJWTKeyResult{err: err}
		return
	}
	firstResultCh <- publishJWTKeyResult{jwtKeys: updatedKeys}

	for {
		resp, err := stream.Recv()
		if err != nil {
			switch {
			case err == io.EOF:
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

		if _, err := u.c.BundleUpdater.AppendJWTKeys(ctx, resp.UpstreamJwtKeys); err != nil {
			u.c.BundleUpdater.LogError(err, "Failed to store JWT keys received by the upstream authority plugin.")
			continue
		}
	}
}

type mintX509CAResult struct {
	x509CA []*x509.Certificate
	err    error
}

func parseMintX509CAFirstResponse(resp *upstreamauthority.MintX509CAResponse) ([]*x509.Certificate, []*x509.Certificate, error) {
	x509CA, err := x509util.RawCertsToCertificates(resp.X509CaChain)
	if err != nil {
		return nil, nil, errs.New("malformed X.509 CA chain: %v", err)
	}
	if len(x509CA) == 0 {
		return nil, nil, errs.New("upstream authority returned empty X.509 CA chain")
	}
	x509Roots, err := parseX509Roots(resp.UpstreamX509Roots)
	if err != nil {
		return nil, nil, err
	}
	return x509CA, x509Roots, nil
}

func parseMintX509CABundleUpdate(resp *upstreamauthority.MintX509CAResponse) ([]*x509.Certificate, error) {
	if len(resp.X509CaChain) > 0 {
		return nil, errs.New("upstream authority returned an X.509 CA chain after the first response")
	}
	return parseX509Roots(resp.UpstreamX509Roots)
}

func parseX509Roots(rawX509Roots [][]byte) ([]*x509.Certificate, error) {
	x509Roots, err := x509util.RawCertsToCertificates(rawX509Roots)
	if err != nil {
		return nil, errs.New("malformed upstream X.509 roots: %v", err)
	}
	if len(x509Roots) == 0 {
		return nil, errs.New("upstream authority returned no upstream X.509 roots")
	}
	return x509Roots, nil
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
