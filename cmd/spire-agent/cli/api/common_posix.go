//go:build !windows
// +build !windows

package api

import (
	"flag"
	"net"

	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
)

// adapterOS has os specific members for the adapter struct
type adapterOS struct {
	socketPath string
}

func (a *adapterOS) addPlatformFlags(flags *flag.FlagSet) {
	flags.StringVar(&a.socketPath, "socketPath", common.DefaultSocketPath, "Path to the SPIRE Agent API socket")
}

func (a *adapterOS) getAddr() (net.Addr, error) {
	return common.GetAddr(a.socketPath)
}
