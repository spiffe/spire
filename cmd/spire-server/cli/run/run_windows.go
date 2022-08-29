//go:build windows
// +build windows

package run

import (
	"errors"
	"flag"
	"net"

	util_cmd "github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/pkg/common/namedpipe"
)

func (c *serverConfig) addOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.Experimental.NamedPipeName, "namedPipeName", "", "Pipe name of the SPIRE Server API named pipe")
}

func (c *serverConfig) getAddr() (net.Addr, error) {
	return namedpipe.AddrFromName(c.Experimental.NamedPipeName), nil
}

func (c *serverConfig) setDefaultsIfNeeded() {
	if c.Experimental.NamedPipeName == "" {
		c.Experimental.NamedPipeName = util_cmd.DefaultNamedPipeName
	}
}

// validateOS performs OS specific validations of the server config
func (c *Config) validateOS() error {
	if c.Server.SocketPath != "" {
		return errors.New("invalid configuration: socket_path is not supported in this platform; please use named_pipe_name instead")
	}
	return nil
}
