//go:build !windows
// +build !windows

package healthcheck

import (
	"flag"
	"net"

	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
)

// healthCheckCommandOS has posix specific implementation
// that complements healthCheckCommand
type healthCheckCommandOS struct {
	socketPath string
}

func (c *healthCheckCommandOS) addOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.socketPath, "socketPath", common.DefaultSocketPath, "Path to the SPIRE Agent API socket")
}

func (c *healthCheckCommandOS) getAddr() (net.Addr, error) {
	return common.GetAddr(c.socketPath)
}
