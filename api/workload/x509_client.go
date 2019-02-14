package workload

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/api/workload/dial"
	"github.com/spiffe/spire/proto/api/workload"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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

	// The maximum number of seconds we should backoff for on dial and rpc calls
	Timeout time.Duration

	// A logging interface which is satisfied by stdlib logger. Can be nil.
	Log logrus.StdLogger
}

func (c *X509ClientConfig) log(format string, args ...interface{}) {
	if c.Log != nil {
		c.Log.Println(fmt.Sprintf(format, args...))
	}
}

// NewX509Client creates a new Workload API client for the X509SVID service.
func NewX509Client(c *X509ClientConfig) *x509Client {
	if c == nil {
		c = new(X509ClientConfig)
	}

	if c.Timeout == 0 {
		c.Timeout = 300 * time.Second
	}

	return &x509Client{
		c:          c,
		updateChan: make(chan *workload.X509SVIDResponse, 1),
	}
}

type x509Client struct {
	c          *X509ClientConfig
	updateChan chan *workload.X509SVIDResponse
	cancel     func()

	mu      sync.RWMutex
	current *workload.X509SVIDResponse
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
	out := make(chan *workload.X509SVIDResponse)
	defer close(out)
	go func() {
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

			// push the update down the channel
			select {
			case x.updateChan <- upd:
			case <-ctx.Done():
				return
			}
		}
	}()

	err := streamX509SVID(ctx, x.c, out)
	switch err {
	case nil, context.Canceled:
		return nil
	default:
		return err
	}
}

func (x *x509Client) Stop() {
	x.mu.RLock()
	if x.cancel != nil {
		x.cancel()
	}
	x.mu.RUnlock()
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

func streamX509SVID(ctx context.Context, config *X509ClientConfig, out chan<- *workload.X509SVIDResponse) error {
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("workload.spiffe.io", "true"))

	conn, err := dial.Dial(ctx, config.Addr)
	if err != nil {
		// dial shouldn't fail unless there is a misconfiguration
		return err
	}
	defer conn.Close()

	// TODO: jitter?
	const backoffMin = time.Second
	backoff := backoffMin

	handleErr := func(ctx context.Context, op string, err error) error {
		switch status.Code(err) {
		case codes.DeadlineExceeded, codes.Canceled:
			return ctx.Err()
		case codes.InvalidArgument:
			return err
		}
		if config.FailOnError {
			config.log("%s failed with %v; aborting", op, err)
			return err
		}

		config.log("%s failed with %v; retrying in %s", op, err, backoff)
		timer := time.NewTimer(backoff)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
		backoff = time.Duration(float64(backoff) * 1.5)
		if backoff > config.Timeout {
			backoff = config.Timeout
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
			select {
			case out <- update:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}
