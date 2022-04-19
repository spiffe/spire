//go:build !windows
// +build !windows

package run

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
	"github.com/spiffe/spire/pkg/common/util"
)

func (c *agentConfig) addOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.SocketPath, "socketPath", "", "Path to bind the SPIRE Agent API socket to")
}

func (c *agentConfig) setPlatformDefaults() {
	c.SocketPath = common.DefaultSocketPath
}

func (c *agentConfig) getAddr() (net.Addr, error) {
	return util.GetUnixAddrWithAbsPath(c.SocketPath)
}

func (c *agentConfig) getAdminAddr() (*net.UnixAddr, error) {
	socketPathAbs, err := filepath.Abs(c.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for socket_path: %w", err)
	}
	adminSocketPathAbs, err := filepath.Abs(c.AdminSocketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for admin_socket_path: %w", err)
	}

	if strings.HasPrefix(adminSocketPathAbs, filepath.Dir(socketPathAbs)+"/") {
		return nil, errors.New("admin socket cannot be in the same directory or a subdirectory as that containing the Workload API socket")
	}

	return &net.UnixAddr{
		Name: adminSocketPathAbs,
		Net:  "unix",
	}, nil
}

// validateOS performs posix specific validations of the agent config
func (c *agentConfig) validateOS() error {
	if c.Experimental.NamedPipeName != "" {
		return errors.New("invalid configuration: named_pipe_name is not supported in this platform; please use socket_path instead")
	}
	return nil
}
