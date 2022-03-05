//go:build !windows
// +build !windows

package api

import (
	"flag"
	"net"

	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
	"github.com/spiffe/spire/pkg/common/util"
)

type watchConfig struct {
	socketPath string
}

func (c *watchConfig) addPlatformFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.socketPath, "socketPath", common.DefaultSocketPath, "Path to the Workload API socket")
}

func (c *watchConfig) getAddr() (net.Addr, error) {
	return util.GetUnixAddrWithAbsPath(c.socketPath)
}
