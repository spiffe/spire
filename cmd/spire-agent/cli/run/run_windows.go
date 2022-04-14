//go:build windows
// +build windows

package run

import (
	"errors"
	"flag"
	"net"

	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
	"github.com/spiffe/spire/pkg/common/util"
)

func (c *agentConfig) addOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.Experimental.NamedPipeName, "namedPipeName", "", "Pipe name to bind the SPIRE Agent API named pipe")
}

func (c *agentConfig) setPlatformDefaults() {
	c.Experimental.NamedPipeName = common.DefaultNamedPipeName
}

func (c *agentConfig) getAddr() (net.Addr, error) {
	return util.GetNamedPipeAddr(c.Experimental.NamedPipeName), nil
}

func (c *agentConfig) getAdminAddr() (*net.UnixAddr, error) {
	return nil, errors.New("admin API: platform not supported")
}

// validateOS performs windows specific validations of the agent config
func (c *agentConfig) validateOS() error {
	if c.SocketPath != "" {
		return errors.New("invalid configuration: socket_path is not supported in this platform; please use named_pipe_socket_path instead")
	}
	return nil
}
