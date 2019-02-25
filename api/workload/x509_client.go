package workload

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/api/workload/dial"
	"github.com/spiffe/spire/proto/api/workload"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	defaultTimeout    = 5 * time.Minute
	defaultBackoffCap = 30 * time.Second
	backoffMin        = time.Second
)

type X509Client interface {
	Start() error
	Stop()

	CurrentSVID() (*workload.X509SVIDResponse, error)
	UpdateChan() <-chan *workload.X509SVIDResponse
}

type X509ClientConfig struct {
	// SPIFFE Workload Endpoint address. Will be read from the
	// `SPIFFE_ENDPOINT_SOCKET` env var if not set.
	Addr net.Addr

	// When true, the client will not attempt to reconnect on error
	FailOnError bool

	// The maximum time to wait before bailing if the workload API is failing.
	// Defaults to 5 minutes if unset. Set to a negative value to disable (in
	// which case the only way to return from Start() is via a call to stop.
	Timeout time.Duration

	// The maximum backoff value between retries. Defaults to 30 seconds.
	BackoffCap time.Duration

	// A logging interface which is satisfied by stdlib logger. Can be nil.
	Log logrus.StdLogger

	// Clock interface used for backoff timing. Can be nil.
	Clock clock.Clock
}

func (c *X509ClientConfig) log(format string, args ...interface{}) {
	if c.Log != nil {
		c.Log.Println(fmt.Sprintf(format, args...))
	}
}

// NewX509Client creates a new Workload API client for the X509SVID service.
func NewX509Client(c *X509ClientConfig) X509Client {
	return newX509Client(c)
}

func newX509Client(c *X509ClientConfig) *x509Client {
	client := &x509Client{
		c:          setX509ClientConfigDefaults(c),
		updateChan: make(chan *workload.X509SVIDResponse, 1),
	}
	client.hooks.streamX509SVID = StreamX509SVID
	return client
}

type x509Client struct {
	c *X509ClientConfig

	// the following are for the duration of Start()
	updateChan chan *workload.X509SVIDResponse
	cancel     func()

	// current is protected by the following mutex
	mu      sync.RWMutex
	current *workload.X509SVIDResponse

	hooks struct {
		streamX509SVID func(context.Context, *X509ClientConfig, chan<- *workload.X509SVIDResponse) error
	}
}

func (x *x509Client) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// make sure the client hasn't already been started
	x.mu.Lock()
	if x.cancel != nil {
		x.mu.Unlock()
		return errors.New("already started")
	}
	x.cancel = cancel
	x.mu.Unlock()

	// allow for another start after this function returns
	defer func() {
		x.mu.Lock()
		x.cancel = nil
		x.mu.Unlock()
	}()

	// set up a channel to receive the updates, update the current
	// update, and push it down the update channel. the channel will
	// be closed when this function returns to terminate this goroutine.
	var wg sync.WaitGroup
	defer wg.Wait()
	out := make(chan *workload.X509SVIDResponse)
	defer close(out)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for upd := range out {
			// set the current update
			x.mu.Lock()
			x.current = upd
			x.mu.Unlock()

			// throw away an existing unread update
			select {
			case <-x.updateChan:
			default:
			}

			// push the update down the channel (should never block since any
			// unread update was drained from the channel and this is the only
			// goroutine sending on the channel)
			x.updateChan <- upd
		}
	}()

	err := x.hooks.streamX509SVID(ctx, x.c, out)
	switch err {
	case nil, context.Canceled:
		return nil
	default:
		return err
	}
}

func (x *x509Client) Stop() {
	x.mu.Lock()
	if x.cancel != nil {
		x.cancel()
	}
	x.mu.Unlock()
}

func (x *x509Client) CurrentSVID() (*workload.X509SVIDResponse, error) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	if x.current == nil {
		return nil, errors.New("no SVID received yet")
	}
	return x.current, nil
}

func (x *x509Client) UpdateChan() <-chan *workload.X509SVIDResponse {
	return x.updateChan
}

func StreamX509SVID(ctx context.Context, config *X509ClientConfig, out chan<- *workload.X509SVIDResponse) error {
	config = setX509ClientConfigDefaults(config)
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("workload.spiffe.io", "true"))

	conn, err := dial.Dial(ctx, config.Addr)
	if err != nil {
		// dial shouldn't fail unless there is a misconfiguration
		return err
	}
	defer conn.Close()

	// TODO: jitter?
	backoff := backoffMin

	lastSuccess := config.Clock.Now()

	handleErr := func(ctx context.Context, op string, err error) error {
		if status.Code(err) == codes.InvalidArgument {
			// Workload API Endpoint specification says to bail on InvalidArgument
			return err
		}
		if config.FailOnError {
			config.log("%s failed with %v; aborting", op, err)
			return err
		}

		// if the context is done, then don't bother setting up the timer.
		// the select below would handle this case but would result in an
		// errant log line (since there would be no retry).
		select {
		case <-ctx.Done():
			config.log("%s failed with %v", op, err)
			return ctx.Err()
		default:
		}

		// Make sure the timeout hasn't been exceeded and cap the backoff to
		// the remaining timeout.
		if config.Timeout > 0 {
			elapsed := config.Clock.Now().Sub(lastSuccess)
			timeoutLeft := config.Timeout - elapsed
			if timeoutLeft <= 0 {
				config.log("%s failed with %v; aborting due to timeout (last success %s ago)", op, err, elapsed)
				return errors.New("timeout exceeded")
			}
			if backoff > timeoutLeft {
				backoff = timeoutLeft
			}
		}

		config.log("%s failed with %v; retrying in %s", op, err, backoff)
		timer := config.Clock.Timer(backoff)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
		backoff = time.Duration(float64(backoff) * 1.5)
		if backoff > config.BackoffCap {
			backoff = config.BackoffCap
		}
		return nil
	}

	client := workload.NewSpiffeWorkloadAPIClient(conn)

retryLoop:
	for {
		stream, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
		if err != nil {
			if err := handleErr(ctx, "FetchX509SVID", err); err != nil {
				return err
			}
			continue
		}

		for {
			update, err := stream.Recv()
			if err != nil {
				if err := handleErr(ctx, "FetchX509SVID.Recv", err); err != nil {
					return err
				}
				continue retryLoop
			}
			backoff = backoffMin
			lastSuccess = config.Clock.Now()
			select {
			case out <- update:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

func setX509ClientConfigDefaults(c *X509ClientConfig) *X509ClientConfig {
	var out *X509ClientConfig
	if c == nil {
		out = new(X509ClientConfig)
	} else {
		dup := *c
		out = &dup
	}

	if out.Timeout == 0 {
		out.Timeout = defaultTimeout
	}
	if out.BackoffCap <= 0 {
		out.BackoffCap = defaultBackoffCap
	}
	if out.BackoffCap < backoffMin {
		out.BackoffCap = backoffMin
	}
	if out.Clock == nil {
		out.Clock = clock.New()
	}
	return out
}
