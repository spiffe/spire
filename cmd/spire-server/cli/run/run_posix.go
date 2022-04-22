//go:build !windows
// +build !windows

package run

import (
	"flag"
	"net"

	"github.com/spiffe/spire/pkg/common/util"
)

const (
	defaultSocketPath = "/tmp/spire-server/private/api.sock"
)

func (c *serverConfig) addOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.SocketPath, "socketPath", "", "Path to bind the SPIRE Server API socket to")
}

func (c *serverConfig) getAddr() (net.Addr, error) {
	return util.GetUnixAddrWithAbsPath(c.SocketPath)
}

func (c *serverConfig) setDefaultsIfNeeded() {
	if c.SocketPath == "" {
		c.SocketPath = defaultSocketPath
	}
}
