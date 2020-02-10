package catalog

import (
	"context"
	"errors"
	"net"
	"sync"
)

type PipeAddr struct {
}

func (PipeAddr) Network() string {
	return "pipe"
}

func (PipeAddr) String() string {
	return "pipe"
}

type PipeNet struct {
	accept    chan net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

func NewPipeNet() *PipeNet {
	return &PipeNet{
		accept: make(chan net.Conn),
		closed: make(chan struct{}),
	}
}

func (n *PipeNet) Addr() net.Addr {
	return PipeAddr{}
}

func (n *PipeNet) Accept() (net.Conn, error) {
	select {
	case s := <-n.accept:
		return s, nil
	case <-n.closed:
		return nil, errors.New("closed")
	}
}

func (n *PipeNet) DialContext(ctx context.Context, addr string) (conn net.Conn, err error) {
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

func (n *PipeNet) Close() error {
	n.closeOnce.Do(func() {
		close(n.closed)
	})
	return nil
}
