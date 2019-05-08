package client

import (
	"sync"

	"google.golang.org/grpc"
)

type nodeConn struct {
	conn     *grpc.ClientConn
	refcount int32
	mu       sync.RWMutex
	alive    bool
}

func newNodeConn(conn *grpc.ClientConn) *nodeConn {
	return &nodeConn{
		alive:    true,
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
	c.release()
	c.mu.Unlock()
}

func (c *nodeConn) release() {
	c.refcount--
	if c.refcount == 0 && c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

func (c *nodeConn) MarkDead() {
	c.mu.Lock()
	if c.alive {
		c.release()
		c.alive = false
	}
	c.mu.Unlock()
}

func (c *nodeConn) IsDead() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return !c.alive
}

func (c *nodeConn) IsReleased() bool {
	if c == nil {
		return true
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn == nil
}
