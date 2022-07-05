//go:build !windows
// +build !windows

package run

import (
	"os"
	"testing"

	"github.com/spiffe/spire/pkg/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	configFile = "../../../../test/fixture/config/server_good_posix.conf"
)

func TestParseFlagsGood(t *testing.T) {
	c, err := parseFlags("run", []string{
		"-bindAddress=127.0.0.1",
		"-socketPath=/tmp/flag.sock",
		"-trustDomain=example.org",
		"-logLevel=INFO",
	}, os.Stderr)
	require.NoError(t, err)
	assert.Equal(t, c.BindAddress, "127.0.0.1")
	assert.Equal(t, c.SocketPath, "/tmp/flag.sock")
	assert.Equal(t, c.TrustDomain, "example.org")
	assert.Equal(t, c.LogLevel, "INFO")
}

func mergeInputCasesOS(t *testing.T) []mergeInputCase {
	return []mergeInputCase{
		{
			msg: "socket_path should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.SocketPath = "foo"
			},
			cliFlags: []string{},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.SocketPath)
			},
		},
		{
			msg:       "socket_path should be configuable by CLI flag",
			fileInput: func(c *Config) {},
			cliFlags:  []string{"-socketPath=foo"},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.SocketPath)
			},
		},
		{
			msg: "socket_path specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Server.SocketPath = "foo"
			},
			cliFlags: []string{"-socketPath=bar"},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "bar", c.Server.SocketPath)
			},
		},
	}
}

func newServerConfigCasesOS() []newServerConfigCase {
	return []newServerConfigCase{
		{
			msg: "socket_path should be correctly configured",
			input: func(c *Config) {
				c.Server.SocketPath = "/foo"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, "/foo", c.BindLocalAddress.String())
				require.Equal(t, "unix", c.BindLocalAddress.Network())
			},
		},
	}
}

func testParseConfigGoodOS(t *testing.T, c *Config) {
	assert.Equal(t, c.Server.SocketPath, "/tmp/spire-server/private/api-test.sock")
}
