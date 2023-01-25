//go:build windows
// +build windows

package run

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/spiffe/spire/pkg/agent"
	"github.com/spiffe/spire/pkg/common/catalog"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/fflag"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/common/namedpipe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			want: want{
				code:           1,
				dataDirCreated: false,
				stderrContent:  "could not find config file",
			},
		},
		{
			name: "don't create any dir when error loading invalid config",
			args: args{
				args: []string{
					"-config", "../../../../test/fixture/config/agent_run_windows.conf",
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
			name: "create data dir and uses named pipe",
			args: args{
				args: []string{
					"-config", "../../../../test/fixture/config/agent_run_windows.conf",
					"-dataDir", testDataDir,
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
			want: want{
				code:           1,
				dataDirCreated: true,
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_ = fflag.Unload()
			os.RemoveAll(testTempDir)

			cmd := &Command{
				logOptions:         testCase.fields.logOptions,
				env:                testCase.fields.env,
				allowUnknownConfig: testCase.fields.allowUnknownConfig,
			}

			result := cmd.Run(testCase.args.args)

			assert.Equal(t, testCase.want.code, result)
			if testCase.want.stderrContent == "" {
				assert.Empty(t, testCase.fields.env.Stderr.(*bytes.Buffer).String())
			} else {
				assert.Contains(t, testCase.fields.env.Stderr.(*bytes.Buffer).String(), testCase.want.stderrContent)
			}
			if testCase.want.dataDirCreated {
				assert.DirExistsf(t, testDataDir, "expected data directory to be created")
			} else {
				assert.NoDirExistsf(t, testDataDir, "expected data directory to not be created")
			}
		})
	}
}

func TestParseFlagsGood(t *testing.T) {
	c, err := parseFlags("run", []string{
		"-dataDir=.",
		"-logLevel=INFO",
		"-serverAddress=127.0.0.1",
		"-serverPort=8081",
		"-namedPipeName=\\spire-agent\\public\\api",
		"-trustBundle=conf/agent/dummy_root_ca.crt",
		"-trustBundleUrl=https://test.url",
		"-trustDomain=example.org",
		"-allowUnauthenticatedVerifiers",
	}, os.Stderr)
	require.NoError(t, err)
	assert.Equal(t, ".", c.DataDir)
	assert.Equal(t, "INFO", c.LogLevel)
	assert.Equal(t, "127.0.0.1", c.ServerAddress)
	assert.Equal(t, 8081, c.ServerPort)
	assert.Equal(t, "\\spire-agent\\public\\api", c.Experimental.NamedPipeName)
	assert.Equal(t, "conf/agent/dummy_root_ca.crt", c.TrustBundlePath)
	assert.Equal(t, "https://test.url", c.TrustBundleURL)
	assert.Equal(t, "example.org", c.TrustDomain)
	assert.Equal(t, true, c.AllowUnauthenticatedVerifiers)
}

func TestParseConfigGood(t *testing.T) {
	c, err := ParseFile("../../../../test/fixture/config/agent_good_windows.conf", false)
	require.NoError(t, err)
	assert.Equal(t, ".", c.Agent.DataDir)
	assert.Equal(t, "INFO", c.Agent.LogLevel)
	assert.Equal(t, "127.0.0.1", c.Agent.ServerAddress)
	assert.Equal(t, 8081, c.Agent.ServerPort)
	assert.Equal(t, "\\spire-agent\\public\\api", c.Agent.Experimental.NamedPipeName)
	assert.Equal(t, "conf/agent/dummy_root_ca.crt", c.Agent.TrustBundlePath)
	assert.Equal(t, "example.org", c.Agent.TrustDomain)
	assert.Equal(t, true, c.Agent.AllowUnauthenticatedVerifiers)
	assert.Equal(t, []string{"c1", "c2", "c3"}, c.Agent.AllowedForeignJWTClaims)

	// Parse/reprint cycle trims outer whitespace
	const data = `join_token = "PLUGIN-AGENT-NOT-A-SECRET"`

	// Check for plugins configurations
	expectedPluginConfigs := catalog.PluginConfigs{
		{
			Type:     "plugin_type_agent",
			Name:     "plugin_name_agent",
			Path:     "./pluginAgentCmd",
			Checksum: "pluginAgentChecksum",
			Data:     data,
			Disabled: false,
		},
		{
			Type:     "plugin_type_agent",
			Name:     "plugin_disabled",
			Path:     ".\\pluginAgentCmd",
			Checksum: "pluginAgentChecksum",
			Data:     data,
			Disabled: true,
		},
		{
			Type:     "plugin_type_agent",
			Name:     "plugin_enabled",
			Path:     "c:/temp/pluginAgentCmd",
			Checksum: "pluginAgentChecksum",
			Data:     data,
			Disabled: false,
		},
	}

	pluginConfigs, err := catalog.PluginConfigsFromHCLNode(c.Plugins)
	require.NoError(t, err)
	require.Equal(t, expectedPluginConfigs, pluginConfigs)
}

func mergeInputCasesOS() []mergeInputCase {
	return []mergeInputCase{
		{
			msg:       "named_pipe_name should default to 8082 if not set",
			fileInput: func(c *Config) {},
			cliInput:  func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "\\spire-agent\\public\\api", c.Agent.Experimental.NamedPipeName)
			},
		},
		{
			msg: "named_pipe_name should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.Experimental.NamedPipeName = "foo"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.Experimental.NamedPipeName)
			},
		},
		{
			msg:       "named_pipe_name should be configuable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *agentConfig) {
				c.Experimental.NamedPipeName = "foo"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.Experimental.NamedPipeName)
			},
		},
		{
			msg: "named_pipe_name specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Agent.Experimental.NamedPipeName = "foo"
			},
			cliInput: func(c *agentConfig) {
				c.Experimental.NamedPipeName = "bar"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "bar", c.Agent.Experimental.NamedPipeName)
			},
		},
		{
			msg: "admin_named_pipe_name should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.Experimental.AdminNamedPipeName = "\\spire-agent\\private\\api-test"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "\\spire-agent\\private\\api-test", c.Agent.Experimental.AdminNamedPipeName)
			},
		},
	}
}

func newAgentConfigCasesOS() []newAgentConfigCase {
	return []newAgentConfigCase{
		{
			msg: "named_pipe_name should be correctly configured",
			input: func(c *Config) {
				c.Agent.Experimental.NamedPipeName = "foo"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, "\\\\.\\pipe\\foo", c.BindAddress.String())
				require.Equal(t, "foo", c.BindAddress.(*namedpipe.Addr).PipeName())
				require.Equal(t, "pipe", c.BindAddress.(*namedpipe.Addr).Network())
			},
		},
		{
			msg: "admin_named_pipe_name not provided",
			input: func(c *Config) {
				c.Agent.Experimental.AdminNamedPipeName = ""
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c.AdminBindAddress)
			},
		},
	}
}
