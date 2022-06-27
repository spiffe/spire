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
	"github.com/spiffe/spire/pkg/agent"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
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

func (c *agentConfig) getAdminAddr() (net.Addr, error) {
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

func (c *agentConfig) hasAdminAddr() bool {
	return c.AdminSocketPath != ""
}

// validateOS performs posix specific validations of the agent config
func (c *agentConfig) validateOS() error {
	if c.Experimental.NamedPipeName != "" {
		return errors.New("invalid configuration: named_pipe_name is not supported in this platform; please use socket_path instead")
	}
	if c.Experimental.AdminNamedPipeName != "" {
		return errors.New("invalid configuration: admin_named_pipe_name is not supported in this platform; please use admin_socket_path instead")
	}
	return nil
}

func prepareEndpoints(c *agent.Config) error {
	// Create uds dir and parents if not exists
	dir := filepath.Dir(c.BindAddress.String())
	if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
		c.Log.WithField("dir", dir).Infof("Creating spire agent UDS directory")
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	// Set umask before starting up the agent
	common_cli.SetUmask(c.Log)

	if c.AdminBindAddress != nil {
		// Create uds dir and parents if not exists
		adminDir := filepath.Dir(c.AdminBindAddress.String())
		if _, statErr := os.Stat(adminDir); os.IsNotExist(statErr) {
			c.Log.WithField("dir", adminDir).Infof("Creating admin UDS directory")
			if err := os.MkdirAll(adminDir, 0755); err != nil {
				return err
			}
		}
	}

	return nil
}
