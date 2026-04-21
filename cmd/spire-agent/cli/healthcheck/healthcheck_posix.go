//go:build !windows

package healthcheck

import (
	"flag"
	"net"

	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
	"github.com/spiffe/spire/pkg/common/util"
)

// healthCheckCommandOS has posix specific implementation
// that complements healthCheckCommand
type healthCheckCommandOS struct {
	socketPath string
	instance   string
}

func (c *healthCheckCommandOS) addOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.socketPath, "socketPath", common.DefaultSocketPath, "Path to the SPIRE Agent API socket")
	flags.StringVar(&c.instance, "instance", "", "Instance name to substitute into socket templates (env SPIRE_AGENT_PUBLIC_SOCKET_TEMPLATE). If omitted and the env var is set, defaults to 'main'.")
}

func (c *healthCheckCommandOS) getAddr() (net.Addr, error) {
	resolved := common.ResolveSocketPath(c.socketPath, common.DefaultSocketPath, "SPIRE_AGENT_PUBLIC_SOCKET_TEMPLATE", c.instance)
	return util.GetUnixAddrWithAbsPath(resolved)
}
