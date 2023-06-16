//go:build windows
// +build windows

package run

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/fflag"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/common/namedpipe"
	"github.com/spiffe/spire/pkg/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	configFile = "../../../../test/fixture/config/server_good_windows.conf"
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
		stderrContent  string
		dataDirCreated bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   want
	}{
		{
			name: "don't create data dir when error loading nonexistent config",
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
			want: want{
				code:           1,
				dataDirCreated: false,
				stderrContent:  "could not find config file",
			},
		},
		{
			name: "don't create data dir when error loading invalid config",
			args: args{
				args: []string{
					"-config", "../../../../test/fixture/config/server_run_windows.conf",
					"-socketPath", "unix:///tmp/agent.sock",
				},
			},
			fields: fields{
				logOptions: []log.Option{},
				env: &commoncli.Env{
					Stderr: new(bytes.Buffer),
				},
				allowUnknownConfig: false,
			},
			want: want{
				code:           1,
				dataDirCreated: false,
				stderrContent:  "flag provided but not defined: -socketPath",
			},
		},
		{
			name: "create data dir when config is loaded",
			args: args{
				args: []string{
					"-config", "../../../../test/fixture/config/server_run_windows.conf",
					"-dataDir", testDataDir,
				},
			},
			fields: fields{
				logOptions: []log.Option{},
				env: &commoncli.Env{
					Stderr: new(bytes.Buffer),
					Stdout: new(bytes.Buffer),
				},
				allowUnknownConfig: false,
			},
			want: want{
				code:           1,
				dataDirCreated: true,
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_ = fflag.Unload()
			os.RemoveAll(testDataDir)

			cmd := &Command{
				logOptions:         testCase.fields.logOptions,
				env:                testCase.fields.env,
				allowUnknownConfig: testCase.fields.allowUnknownConfig,
			}

			code := cmd.Run(testCase.args.args)

			assert.Equal(t, testCase.want.code, code)
			if testCase.want.stderrContent == "" {
				assert.Empty(t, testCase.fields.env.Stderr.(*bytes.Buffer).String())
			} else {
				assert.Contains(t, testCase.fields.env.Stderr.(*bytes.Buffer).String(), testCase.want.stderrContent)
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

func mergeInputCasesOS(*testing.T) []mergeInputCase {
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
				require.Equal(t, "\\foo", namedpipe.GetPipeName(c.BindLocalAddress.String()))
				require.Equal(t, "pipe", c.BindLocalAddress.Network())
			},
		},
	}
}

func testParseConfigGoodOS(t *testing.T, c *Config) {
	assert.Equal(t, c.Server.Experimental.NamedPipeName, "\\spire-server\\private\\api-test")
}
