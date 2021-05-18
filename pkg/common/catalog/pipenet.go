package catalog

import (
	"context"
	"errors"
	"net"
	"sync"
)

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

type pipeNet struct {
	accept    chan net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

func newPipeNet() *pipeNet {
	return &pipeNet{
		accept: make(chan net.Conn),
		closed: make(chan struct{}),
	}
}

func (n *pipeNet) Addr() net.Addr {
	return pipeAddr{}
}

func (n *pipeNet) Accept() (net.Conn, error) {
	select {
	case s := <-n.accept:
		return s, nil
	case <-n.closed:
		return nil, errors.New("closed")
	}
}

func (n *pipeNet) DialContext(ctx context.Context, addr string) (conn net.Conn, err error) {
	c, s := net.Pipe()

	defer func() {
		if err != nil {
			c.Close()
			s.Close()
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case n.accept <- s:
		return c, nil
	case <-n.closed:
		return nil, errors.New("network closed")
	}
}

func (n *pipeNet) Close() error {
	n.closeOnce.Do(func() {
		close(n.closed)
	})
	return nil
}
