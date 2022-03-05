//go:build windows
// +build windows

package api

import (
	"flag"
	"net"

	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
)

// adapterOS has os specific implementation that
// complements adapter
type adapterOS struct {
	tcpSocketPort int
}

func (a *adapterOS) addPlatformFlags(flags *flag.FlagSet) {
	flags.IntVar(&a.tcpSocketPort, "tcpSocketPort", common.DefaultTCPSocketPort, "Port number of the local address to bind the SPIRE Agent API socket to")
}

func (a *adapterOS) getAddr() (net.Addr, error) {
	return common.GetAddr(a.tcpSocketPort)
}
