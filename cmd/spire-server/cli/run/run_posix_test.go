//go:build !windows
// +build !windows

package run

import (
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"

	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	configFile = "../../../../test/fixture/config/server_good_posix.conf"
)

func TestCommand_Run(t *testing.T) {
	testTempDir := t.TempDir()
	testDataDir := fmt.Sprintf("%s/data", testTempDir)

	type fields struct {
		logOptions         []log.Option
		env                *commoncli.Env
		allowUnknownConfig bool
	}
	type args struct {
		args []string
	}
	type want struct {
		code           int
		dataDirCreated bool
	}
	tests := []struct {
		name         string
		fields       fields
		args         args
		configLoaded bool
		want         want
	}{
		{
			name: "error loading config settings on linux",
			args: args{
				args: []string{},
			},
			fields: fields{
				logOptions: []log.Option{},
				env: &commoncli.Env{
					Stderr: io.Discard,
				},
				allowUnknownConfig: false,
			},
			configLoaded: false,
			want: want{
				code:           1,
				dataDirCreated: false,
			},
		},
		{
			name: "success loading config settings on linux",
			args: args{
				args: []string{
					"-config", "../../../../test/fixture/config/server_run_posix.conf",
					"-dataDir", testDataDir,
				},
			},
			fields: fields{
				logOptions: []log.Option{},
				env: &commoncli.Env{
					Stderr: io.Discard,
				},
				allowUnknownConfig: false,
			},
			configLoaded: true,
			want: want{
				code:           1,
				dataDirCreated: true,
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {

			os.RemoveAll(testDataDir)

			cmd := &Command{
				logOptions:         testCase.fields.logOptions,
				env:                testCase.fields.env,
				allowUnknownConfig: testCase.fields.allowUnknownConfig,
			}

			assert.Equalf(t, testCase.want.code, cmd.Run(testCase.args.args), "Run(%v)", testCase.args.args)
			if testCase.configLoaded {
				currentUmask := syscall.Umask(0)
				assert.Equalf(t, currentUmask, 0027, "spire-agent processes should have been created with 0027 umask")
			}
			if testCase.want.dataDirCreated {
				assert.DirExistsf(t, testDataDir, "data directory should be created")
			} else {
				assert.NoDirExistsf(t, testDataDir, "data directory should not be created")
			}
		})
	}
}

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
