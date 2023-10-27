//go:build windows

package run

import (
	"errors"
	"flag"
	"net"

	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
	"github.com/spiffe/spire/pkg/agent"
	"github.com/spiffe/spire/pkg/common/namedpipe"
)

func (c *agentConfig) addOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.Experimental.NamedPipeName, "namedPipeName", "", "Pipe name to bind the SPIRE Agent API named pipe")
}

func (c *agentConfig) setPlatformDefaults() {
	c.Experimental.NamedPipeName = common.DefaultNamedPipeName
}

func (c *agentConfig) getAddr() (net.Addr, error) {
	return namedpipe.AddrFromName(c.Experimental.NamedPipeName), nil
}

func (c *agentConfig) getAdminAddr() (net.Addr, error) {
	return namedpipe.AddrFromName(c.Experimental.AdminNamedPipeName), nil
}

func (c *agentConfig) hasAdminAddr() bool {
	return c.Experimental.AdminNamedPipeName != ""
}

// validateOS performs windows specific validations of the agent config
func (c *agentConfig) validateOS() error {
	if c.SocketPath != "" {
		return errors.New("invalid configuration: socket_path is not supported in this platform; please use named_pipe_name instead")
	}
	if c.AdminSocketPath != "" {
		return errors.New("invalid configuration: admin_socket_path is not supported in this platform; please use admin_named_pipe_name instead")
	}
	return nil
}

func prepareEndpoints(*agent.Config) error {
	// Nothing to do in this platform
	return nil
}
