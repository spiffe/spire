//go:build windows
// +build windows

package healthcheck

import (
	"flag"
	"net"

	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
)

// healthCheckCommandOS has os specific members
// that complement healthCheckCommand
type healthCheckCommandOS struct {
	tcpSocketPort int
}

func (c *healthCheckCommandOS) addPlatformFlags(flags *flag.FlagSet) {
	flags.IntVar(&c.tcpSocketPort, "tcpSocketPort", common.DefaultTCPSocketPort, "TCP port number of the SPIRE Agent API socket")
}

func (c *healthCheckCommandOS) getAddr() (net.Addr, error) {
	return common.GetAddr(c.tcpSocketPort)
}
