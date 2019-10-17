package catalog

import (
	"errors"
	"net"
	"sync"
	"time"
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

func (n *PipeNet) Dial(addr string, timeout time.Duration) (conn net.Conn, err error) {
	c, s := net.Pipe()

	t := time.NewTimer(timeout)
	defer func() {
		t.Stop()
		if err != nil {
			c.Close()
			s.Close()
		}
	}()

	select {
	case <-t.C:
		return nil, errors.New("timed out")
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
