//go:build !windows

package common

import (
	"flag"
	"net"

	"github.com/spiffe/spire/pkg/common/util"
)

type ConfigOS struct {
	socketPath string
}

func (c *ConfigOS) AddOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.socketPath, "socketPath", DefaultSocketPath, "Path to the SPIRE Agent API Unix domain socket")
}

func (c *ConfigOS) GetAddr() (net.Addr, error) {
	return util.GetUnixAddrWithAbsPath(c.socketPath)
}

func (c *ConfigOS) GetTargetName() (string, error) {
	addr, err := util.GetUnixAddrWithAbsPath(c.socketPath)
	if err != nil {
		return "", err
	}
	return util.GetTargetName(addr)
}
