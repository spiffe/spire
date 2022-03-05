//go:build windows
// +build windows

package run

import (
	"errors"
	"flag"
	"net"

	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
)

func (c *agentConfig) addPlatformFlags(flags *flag.FlagSet) {
	flags.IntVar(&c.Experimental.TCPSocketPort, "tcpSocketPort", 0, "TCP port number of the local address to bind the SPIRE Agent API socket to")
}

func (c *agentConfig) setPlatformDefaults() {
	c.Experimental.TCPSocketPort = common.DefaultTCPSocketPort
}

func (c *agentConfig) getAddr() (net.Addr, error) {
	return common.GetAddr(c.Experimental.TCPSocketPort)
}

func (c *agentConfig) getAdminAddr() (*net.UnixAddr, error) {
	return &net.UnixAddr{
		Name: c.AdminSocketPath,
		Net:  "unix",
	}, nil
}

// validateOS performs os specific validations of the agent config
func (c *agentConfig) validateOS() error {
	if c.SocketPath != "" {
		return errors.New("ivalid configuration: socket_path is not supported in this platform; please use tcp_socket_port instead")
	}
	return nil
}
