package workload

import (
	"context"
	"fmt"

	"github.com/spiffe/spire/api/workload/dial"
	"github.com/spiffe/spire/proto/api/workload"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// x509Stream maintains an open connection to the X509-SVID service of the SPIFFE Workload API and
// listens for updates. Received messages are passed to the x509Handler, whose update channel is
// exposed by *x509Stream.updatechan().
type x509Stream struct {
	c *X509ClientConfig

	handler  *x509Handler
	stopChan chan struct{}

	wlClient workload.SpiffeWorkloadAPIClient
	wlStream workload.SpiffeWorkloadAPI_FetchX509SVIDClient
	wlCancel context.CancelFunc
}

// newX509Stream initializes a new x509Stream struct using the provided x509ClientConfig.
func newX509Stream(c *X509ClientConfig) *x509Stream {
	return &x509Stream{
		c:        c,
		handler:  newX509Handler(),
		stopChan: make(chan struct{}),
	}
}

// listen dials the SPIFFE Workload Endpoint and attaches to the X509-SVID service. It processes updates
// and retries failed operations as necessary. This method blocks until the stream is stopped or a fatal
// error is encountered.
func (x *x509Stream) listen() error {
	var err error
	bo := newBackoff(x.c.Timeout)

	x.handler.start()

	for {
		x.wlClient, err = x.newClient()
		if err == context.Canceled {
			return nil
		}
		if err != nil {
			x.log("Retry limit exceeded while trying to dial SPIFFE Workload Endpoint. Giving up.")
			return err
		}

		for {
			x.wlStream, x.wlCancel, err = x.newStream()
			if err == context.Canceled {
				return nil
			}
			if err != nil {
				x.log("Retry limit exceeded while trying to fetch X509-SVID stream. Redialing.")
				break
			}

			for {
				update, err := x.recv()
				if err == context.Canceled {
					return nil
				}
				if err != nil && x.goAgain(bo) {
					break
				}
				if err != nil {
					x.log("Retry limit exceeded while trying to read X509-SVID stream. Giving up.")
					return err
				}

				bo.reset()
				x.handler.update(update)
			}
		}
	}
}

// stop signals cancellation to all pending operations, and unblocks listen().
func (x *x509Stream) stop() {
	close(x.stopChan)
}

// updateChan returns a channel over which updates will be delivered.
func (x *x509Stream) updateChan() <-chan *workload.X509SVIDResponse {
	return x.handler.updateChan()
}

// newClient creates a new SPIFFE Workload API client by dialing the Workload Endpoint, applying
// a backoff if an error is encountered.
func (x *x509Stream) newClient() (workload.SpiffeWorkloadAPIClient, error) {
	bo := newBackoff(x.c.Timeout)

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	connChan := make(chan *grpc.ClientConn, 1)
	errChan := make(chan error, 1)

	getConn := func() {
		conn, err := dial.Dial(ctx, x.c.Addr)
		if err != nil {
			x.log(fmt.Sprintf("Error dialing SPIFFE Workload Endpoint: %v", err))
			errChan <- err
			return
		}

		connChan <- conn
	}

	for {
		go getConn()

		select {
		case conn := <-connChan:
			return workload.NewSpiffeWorkloadAPIClient(conn), nil
		case err := <-errChan:
			if x.goAgain(bo) {
				continue
			}
			return nil, err
		case <-x.stopChan:
			cancel()
			return nil, context.Canceled
		}
	}
}

// newStream creates a new X509-SVID stream by calling the appropriate endpoint on the SPIFFE Workload API client, applying
// a backoff if an error is encountered.
func (x *x509Stream) newStream() (workload.SpiffeWorkloadAPI_FetchX509SVIDClient, context.CancelFunc, error) {
	bo := newBackoff(x.c.Timeout)

	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("workload.spiffe.io", "true"))
	ctx, cancel := context.WithCancel(ctx)

	streamChan := make(chan workload.SpiffeWorkloadAPI_FetchX509SVIDClient, 1)
	errChan := make(chan error, 1)

	getStream := func() {
		stream, err := x.wlClient.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
		if err != nil {
			x.log(fmt.Sprintf("Error establishing X509-SVID stream: %v", err))
			errChan <- err
			return
		}

		streamChan <- stream
	}

	for {
		go getStream()

		select {
		case stream := <-streamChan:
			return stream, cancel, nil
		case err := <-errChan:
			if x.goAgain(bo) {
				continue
			}
			return nil, nil, err
		case <-x.stopChan:
			cancel()
			return nil, nil, context.Canceled
		}
	}
}

// recv blocks on the X509-SVID stream and waits for a message to be received.
func (x *x509Stream) recv() (*workload.X509SVIDResponse, error) {
	respChan := make(chan *workload.X509SVIDResponse, 1)
	errChan := make(chan error, 1)

	getUpdate := func() {
		update, err := x.wlStream.Recv()
		if err != nil {
			x.log(fmt.Sprintf("Received error from X509-SVID stream: %v", err))
			errChan <- err
			return
		}

		respChan <- update
	}

	go getUpdate()
	select {
	case resp := <-respChan:
		return resp, nil
	case err := <-errChan:
		return nil, err
	case <-x.stopChan:
		x.wlCancel()
		return nil, context.Canceled
	}
}

// goAgain determines whether an operation should be retried or not. If necessary, it will
// sleep for the backoff period.
func (x *x509Stream) goAgain(bo *backoff) bool {
	if x.c.FailOnError || bo.expired() {
		return false
	}

	select {
	case <-bo.ticker():
		return true
	case <-x.stopChan:
		return false
	}
}

// log records a log line if a logger is configured.
func (x *x509Stream) log(msg string) {
	if x.c.Log != nil {
		x.c.Log.Println(msg)
	}
}
