package workload

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/proto/api/workload"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type Client interface {
	Start() error
	Shutdown()
	UpdateChan() <-chan *workload.X509SVIDResponse
}

type ClientConfig struct {
	// SPIFFE Workload Endpoint address. Will be read from the
	// `SPIFFE_ENDPOINT_SOCKET` env var if not set.
	Addr net.Addr

	// When true, the client will not attempt to reconnect on error
	FailOnError bool

	// The maximum number of seconds we should backoff for on dial and rpc calls
	Timeout time.Duration

	// A logging interface which is satisfied by stdlib logger. Can be nil.
	Logger logrus.StdLogger
}

type client struct {
	c   *ClientConfig
	mtx *sync.RWMutex

	current *workload.X509SVIDResponse

	updateChan    chan *workload.X509SVIDResponse
	updatePending chan struct{}
	shutdown      chan struct{}
}

// NewClient creates a new Workload API client.
func NewClient(c *ClientConfig) Client {
	if c == nil {
		c = new(ClientConfig)
	}

	if c.Timeout == 0 {
		c.Timeout = 300 * time.Second
	}

	return &client{
		c:             c,
		mtx:           new(sync.RWMutex),
		updateChan:    make(chan *workload.X509SVIDResponse),
		updatePending: make(chan struct{}, 1),
		shutdown:      make(chan struct{}),
	}
}

// Start runs the SPIFFE Workload API client. This method blocks until an error is encountered,
// or the client is shut down.
func (c *client) Start() error {
	respChan := make(chan *workload.X509SVIDResponse)
	errChan := make(chan error)
	header := metadata.Pairs("workload.spiffe.io", "true")

	go c.updater()
	for {
		apiClient, err := c.dialWithBackoff()
		if err != nil {
			return err
		}

	FetchLoop:
		for {
			ctx := context.Background()
			ctx = metadata.NewOutgoingContext(ctx, header)
			ctx, cancel := context.WithCancel(ctx)
			stream, err := c.fetchWithBackoff(ctx, apiClient)
			if err != nil {
				return err
			}

		RecvLoop:
			for {
				go c.recv(stream, respChan, errChan)

				var resp *workload.X509SVIDResponse
				select {
				case <-c.shutdown:
					cancel()
					return nil
				case err := <-errChan:
					cancel()
					if err == io.EOF {
						c.log("SPIFFE server hung up. Redialing.")
						break FetchLoop
					} else {
						msg := fmt.Sprintf("Received error from SPIFFE Workload API: %v", err)
						c.log(msg)
						break RecvLoop
					}
				case resp = <-respChan:
				}

				c.mtx.Lock()
				c.current = resp
				c.mtx.Unlock()

				// Don't block if channel is full
				select {
				case c.updatePending <- struct{}{}:
				default:
				}
			}
		}
	}
}

func (c *client) Shutdown() {
	close(c.shutdown)
}

func (c *client) UpdateChan() <-chan *workload.X509SVIDResponse {
	return c.updateChan
}

// updater implements a waiter which attempts to send the consumer a copy of the latest response. It
// is decoupled from updates being received from the Workload API in order to be easier on the node agent,
// ensuring updates are read in a timely fashion.
func (c *client) updater() {
	for {
		select {
		case <-c.shutdown:
			return
		case <-c.updatePending:
		}

	Update:
		c.mtx.RLock()
		update := c.current
		c.mtx.RUnlock()

		select {
		case <-c.shutdown:
			return
		case <-c.updatePending:
			// If we get another update before the consumer has
			// read the current one, re-evaluate the update.
			goto Update
		case c.updateChan <- update:
		}
	}
}

func (c *client) recv(stream workload.SpiffeWorkloadAPI_FetchX509SVIDClient, respChan chan *workload.X509SVIDResponse, errChan chan error) {
	resp, err := stream.Recv()
	if err != nil {
		errChan <- err
		return
	}

	respChan <- resp
	return
}

func (c *client) fetchWithBackoff(ctx context.Context, apiClient workload.SpiffeWorkloadAPIClient) (workload.SpiffeWorkloadAPI_FetchX509SVIDClient, error) {
	b := newBackoff(c.c.Timeout, c.c.FailOnError)

	for {
		stream, err := apiClient.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
		if err != nil && b.goAgain(c.shutdown) {
			msg := fmt.Sprintf("Received error from SPIFFE Workload API: %v", err)
			c.log(msg)
			continue
		} else if err != nil {
			return nil, err
		}

		return stream, nil
	}
}

func (c *client) dialWithBackoff() (workload.SpiffeWorkloadAPIClient, error) {
	b := newBackoff(c.c.Timeout, c.c.FailOnError)

	for {
		apiClient, err := c.dial()
		if err != nil && b.goAgain(c.shutdown) {
			msg := fmt.Sprintf("Received error while dialing SPIFFE Workload API: %v", err)
			c.log(msg)
			continue
		} else if err != nil {
			return nil, err
		}

		return apiClient, nil
	}
}

func (c *client) dial() (workload.SpiffeWorkloadAPIClient, error) {
	addr, err := c.addr()
	if err != nil {
		return nil, err
	}

	// Workload API is unauthenticated
	dialer := c.dialer(addr.Network())
	conn, err := grpc.Dial(addr.String(), grpc.WithInsecure(), grpc.WithDialer(dialer))
	if err != nil {
		return nil, err
	}

	return workload.NewSpiffeWorkloadAPIClient(conn), nil
}

func (c *client) addr() (net.Addr, error) {
	if c.c.Addr != nil {
		return c.c.Addr, nil
	}

	return c.addrFromEnv()
}

func (c *client) log(msg string) {
	if c.c.Logger != nil {
		c.c.Logger.Println(msg)
	}
}

func (c client) addrFromEnv() (net.Addr, error) {
	val, ok := os.LookupEnv("SPIFFE_ENDPOINT_SOCKET")
	if !ok {
		return nil, errors.New("socket address not configured")
	}

	u, err := url.Parse(val)
	if err != nil {
		return nil, fmt.Errorf("parse address from env: %v", err)
	}

	switch u.Scheme {
	case "tcp":
		return c.parseTCPAddr(u)
	case "unix":
		return c.parseUDSAddr(u)
	default:
		return nil, fmt.Errorf("unsupported network type: %v", u.Scheme)
	}
}

func (client) parseTCPAddr(u *url.URL) (net.Addr, error) {
	parts := strings.Split(u.Host, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("address must be defined as ip:port; got: %v", u.Host)
	}

	ip := net.ParseIP(parts[0])
	if ip == nil {
		return nil, fmt.Errorf("tcp address is not an IP: %v", parts[0])
	}

	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("tcp port is not an integer: %v", err)
	}

	addr := &net.TCPAddr{
		IP:   ip,
		Port: port,
	}

	return addr, nil
}

func (client) parseUDSAddr(u *url.URL) (net.Addr, error) {
	if u.Host != "" {
		return nil, fmt.Errorf("unexpected authority component in unix uri: %v", u.Host)
	}

	if u.Path == "" {
		return nil, errors.New("no path defined for unix uri")
	}

	if u.Path[0] != '/' {
		return nil, fmt.Errorf("unix socket path not absolute: %v", u.Path)
	}

	addr := &net.UnixAddr{
		Net:  "unix",
		Name: u.Path,
	}

	return addr, nil
}

func (client) dialer(network string) func(addr string, timeout time.Duration) (net.Conn, error) {
	return func(addr string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout(network, addr, timeout)
	}
}
