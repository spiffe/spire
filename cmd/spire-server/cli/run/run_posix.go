//go:build !windows

package run

import (
	"errors"
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

// validateOS performs OS specific validations of the server config
func (c *Config) validateOS() error {
	if c.Server.Experimental.NamedPipeName != "" {
		return errors.New("invalid configuration: named_pipe_name is not supported in this platform; please use socket_path instead")
	}
	return nil
}
