package workload

import (
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/proto/api/workload"
)

type X509Client interface {
	Start() error
	Stop()
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

// NewX509Client creates a new Workload API client for the X509SVID service.
func NewX509Client(c *X509ClientConfig) *x509Client {
	if c == nil {
		c = new(X509ClientConfig)
	}

	if c.Timeout == 0 {
		c.Timeout = 300 * time.Second
	}

	return &x509Client{
		c:        c,
		stopChan: make(chan struct{}),
		stream:   newX509Stream(c),
	}
}

type x509Client struct {
	c        *X509ClientConfig
	stopChan chan struct{}

	stream *x509Stream
}

func (x *x509Client) Start() error {
	errChan := make(chan error, 1)
	go func() { errChan <- x.stream.listen() }()
	defer x.stream.stop()

	select {
	case <-x.stopChan:
		return nil
	case err := <-errChan:
		return err
	}
}

func (x *x509Client) Stop() {
	close(x.stopChan)
}

func (x *x509Client) UpdateChan() <-chan *workload.X509SVIDResponse {
	return x.stream.updateChan()
}
