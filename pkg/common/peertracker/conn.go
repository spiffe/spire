package peertracker

import (
	"net"
	"time"
)

var _ net.Conn = &Conn{}

type Conn struct {
	c    net.Conn
	Info AuthInfo
}

func (c *Conn) Read(b []byte) (int, error) {
	return c.c.Read(b)
}

func (c *Conn) Write(b []byte) (int, error) {
	return c.c.Write(b)
}

func (c *Conn) Close() error {
	c.Info.Watcher.Close()
	return c.c.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	return c.c.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.c.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.c.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}
