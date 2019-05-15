package client

import (
	"sync"

	"google.golang.org/grpc"
)

type nodeConn struct {
	conn     *grpc.ClientConn
	refcount int32
	mu       sync.RWMutex
}

func newNodeConn(conn *grpc.ClientConn) *nodeConn {
	return &nodeConn{
		conn:     conn,
		refcount: 1,
	}
}

func (c *nodeConn) AddRef() {
	c.mu.Lock()
	c.refcount++
	c.mu.Unlock()
}

func (c *nodeConn) Release() {
	c.mu.Lock()
	c.refcount--
	if c.refcount == 0 && c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.mu.Unlock()
}

func (c *nodeConn) Conn() *grpc.ClientConn {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn
}
