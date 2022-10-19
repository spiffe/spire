//go:build !windows
// +build !windows

package run

import (
	"bytes"
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"

	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/fflag"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	configFile  = "../../../../test/fixture/config/server_good_posix.conf"
	testTempDir = "/tmp/spire-server-test"
)

func TestCommand_Run(t *testing.T) {
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
		dataDirCreated string
		stderrContent  string
	}
	tests := []struct {
		name         string
		fields       fields
		args         args
		configLoaded bool
		want         want
	}{
		{
			name: "don't create any dir when error loading nonexistent config",
			args: args{
				args: []string{},
			},
			fields: fields{
				logOptions: []log.Option{},
				env: &commoncli.Env{
					Stderr: new(bytes.Buffer),
				},
				allowUnknownConfig: false,
			},
			configLoaded: false,
			want: want{
				code:          1,
				stderrContent: "could not find config file",
			},
		},
		{
			name: "don't create any dir when error loading invalid config",
			args: args{
				args: []string{
					"-config", "../../../../test/fixture/config/agent_run_posix.conf",
					"-namedPipeName", "\\spire-agent\\public\\api",
				},
			},
			fields: fields{
				logOptions: []log.Option{},
				env: &commoncli.Env{
					Stderr: new(bytes.Buffer),
				},
				allowUnknownConfig: false,
			},
			configLoaded: false,
			want: want{
				code:          1,
				stderrContent: "flag provided but not defined: -namedPipeName",
			},
		},
		{
			name: "create data dir when config is loaded and server crashes",
			args: args{
				args: []string{
					"-config", "../../../../test/fixture/config/server_run_posix.conf",
					"-dataDir", fmt.Sprintf("%s/wrong/data/dir", testTempDir),
				},
			},
			fields: fields{
				logOptions: []log.Option{},
				env: &commoncli.Env{
					Stderr: new(bytes.Buffer),
				},
				allowUnknownConfig: false,
			},
			configLoaded: true,
			want: want{
				code:           1,
				dataDirCreated: fmt.Sprintf("%s/wrong/data/dir", testTempDir),
			},
		},
		{
			name: "create data dir when config is loaded and server stops",
			args: args{
				args: []string{
					"-config", "../../../../test/fixture/config/server_run_posix.conf",
					"-dataDir", fmt.Sprintf("%s/data", testTempDir),
				},
			},
			fields: fields{
				logOptions: []log.Option{},
				env: &commoncli.Env{
					Stderr: new(bytes.Buffer),
				},
				allowUnknownConfig: false,
			},
			configLoaded: true,
			want: want{
				code:           0,
				dataDirCreated: fmt.Sprintf("%s/data", testTempDir),
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_ = fflag.Unload()
			os.RemoveAll(testTempDir)
			defer os.RemoveAll(testTempDir)

			cmd := &Command{
				logOptions:         testCase.fields.logOptions,
				env:                testCase.fields.env,
				allowUnknownConfig: testCase.fields.allowUnknownConfig,
			}

			go func() {
				time.Sleep(1 * time.Second)
				err := syscall.Kill(syscall.Getpid(), syscall.SIGINT)
				if err != nil {
					t.Errorf("Failed to kill process: %v", err)
				}
			}()

			code := cmd.Run(testCase.args.args)

			assert.Equal(t, testCase.want.code, code)
			if testCase.want.stderrContent == "" {
				assert.Empty(t, testCase.fields.env.Stderr.(*bytes.Buffer).String())
			} else {
				assert.Contains(t, testCase.fields.env.Stderr.(*bytes.Buffer).String(), testCase.want.stderrContent)
			}
			if testCase.want.dataDirCreated != "" {
				assert.DirExistsf(t, testCase.want.dataDirCreated, "data directory should be created")
				currentUmask := syscall.Umask(0)
				assert.Equalf(t, currentUmask, 0027, "spire-server process should have been created with 0027 umask")
			} else {
				assert.NoDirExistsf(t, testCase.want.dataDirCreated, "data directory should not be created")
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
