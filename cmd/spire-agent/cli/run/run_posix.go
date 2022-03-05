//go:build !windows
// +build !windows

package run

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
)

func (c *agentConfig) addPlatformFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.SocketPath, "socketPath", "", "Path to bind the SPIRE Agent API socket to")
}

func (c *agentConfig) setPlatformDefaults() {
	c.SocketPath = common.DefaultSocketPath
}

func (c *agentConfig) getAddr() (net.Addr, error) {
	return common.GetAddr(c.SocketPath)
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

	if strings.HasPrefix(adminSocketPathAbs, filepath.Dir(socketPathAbs)+string(os.PathSeparator)) {
		return nil, errors.New("admin socket cannot be in the same directory or a subdirectory as that containing the Workload API socket")
	}

	return &net.UnixAddr{
		Name: adminSocketPathAbs,
		Net:  "unix",
	}, nil
}

// validateOS performs os specific validations of the agent config
func (c *agentConfig) validateOS() error {
	if c.Experimental.TCPSocketPort != 0 {
		return errors.New("ivalid configuration: tcp_socket_port is not supported in this platform; please use socket_path instead")
	}
	return nil
}
