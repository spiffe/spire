//go:build !windows

package common

import (
	"flag"
	"net"

	"github.com/spiffe/spire/pkg/common/util"
)

type ConfigOS struct {
	socketPath string
	instance   string
}

func (c *ConfigOS) AddOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.socketPath, "socketPath", DefaultSocketPath, "Path to the SPIRE Agent API Unix domain socket")
	flags.StringVar(&c.instance, "instance", "", "Instance name to substitute into socket templates (env SPIRE_AGENT_PUBLIC_SOCKET_TEMPLATE).")
}

func (c *ConfigOS) GetAddr() (net.Addr, error) {
	resolved, err := ResolveSocketPath(c.socketPath, DefaultSocketPath, "SPIRE_AGENT_PUBLIC_SOCKET_TEMPLATE", c.instance)
	if err != nil {
		return nil, err
	}
	return util.GetUnixAddrWithAbsPath(resolved)
}

func (c *ConfigOS) GetTargetName() (string, error) {
	addr, err := c.GetAddr()
	if err != nil {
		return "", err
	}
	return util.GetTargetName(addr)
}
