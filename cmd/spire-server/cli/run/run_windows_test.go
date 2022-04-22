//go:build windows
// +build windows

package run

import (
	"os"
	"testing"

	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	configFile = "../../../../test/fixture/config/server_good_windows.conf"
)

func TestParseFlagsGood(t *testing.T) {
	c, err := parseFlags("run", []string{
		"-bindAddress=127.0.0.1",
		"-namedPipeName=\\tmp\\flag",
		"-trustDomain=example.org",
		"-logLevel=INFO",
	}, os.Stderr)
	require.NoError(t, err)
	assert.Equal(t, c.BindAddress, "127.0.0.1")
	assert.Equal(t, c.Experimental.NamedPipeName, "\\tmp\\flag")
	assert.Equal(t, c.TrustDomain, "example.org")
	assert.Equal(t, c.LogLevel, "INFO")
}

func mergeInputCasesOS(t *testing.T) []mergeInputCase {
	return []mergeInputCase{
		{
			msg: "named_pipe_name should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.Experimental.NamedPipeName = "foo"
			},
			cliFlags: []string{},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.Experimental.NamedPipeName)
			},
		},
		{
			msg:       "named_pipe_name be configuable by CLI flag",
			fileInput: func(c *Config) {},
			cliFlags:  []string{"-namedPipeName=foo"},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.Experimental.NamedPipeName)
			},
		},
		{
			msg: "named_pipe_name specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Server.Experimental.NamedPipeName = "foo"
			},
			cliFlags: []string{"-namedPipeName=bar"},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "bar", c.Server.Experimental.NamedPipeName)
			},
		},
	}
}

func newServerConfigCasesOS() []newServerConfigCase {
	return []newServerConfigCase{
		{
			msg: "named_pipe_name should be correctly configured",
			input: func(c *Config) {
				c.Server.Experimental.NamedPipeName = "\\foo"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, "\\foo", util.GetPipeName(c.BindLocalAddress.String()))
				require.Equal(t, "pipe", c.BindLocalAddress.Network())
			},
		},
	}
}

func testParseConfigGoodOS(t *testing.T, c *Config) {
	assert.Equal(t, c.Server.Experimental.NamedPipeName, "\\spire-server\\private\\api-test")
}
