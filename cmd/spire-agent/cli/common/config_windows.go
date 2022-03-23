//go:build windows
// +build windows

package common

import (
	"flag"
	"net"
)

type ConfigOS struct {
	tcpSocketPort int
}

func (c *ConfigOS) AddOSFlags(flags *flag.FlagSet) {
	flags.IntVar(&c.tcpSocketPort, "tcpSocketPort", DefaultTCPSocketPort, "Localhost port of the SPIRE Agent API TCP socket")
}

func (c *ConfigOS) GetAddr() (net.Addr, error) {
	return GetAddr(c.tcpSocketPort)
}
