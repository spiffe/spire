package peertracker

import (
	"net"
)

type Conn struct {
	net.Conn
	Info AuthInfo
}

func (c *Conn) Close() error {
	c.Info.Watcher.Close()
	return c.Conn.Close()
}
