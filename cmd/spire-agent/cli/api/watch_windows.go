//go:build windows
// +build windows

package api

import (
	"flag"
	"net"

	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
)

type watchConfig struct {
	tcpSocketPort int
}

func (c *watchConfig) addPlatformFlags(flags *flag.FlagSet) {
	flags.IntVar(&c.tcpSocketPort, "tcpSocketPort", common.DefaultTCPSocketPort, "TCP port number of the Workload API socket")
}

func (c *watchConfig) getAddr() (net.Addr, error) {
	return common.GetAddr(c.tcpSocketPort)
}
