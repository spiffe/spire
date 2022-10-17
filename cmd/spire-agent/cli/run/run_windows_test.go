//go:build windows
// +build windows

package run

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/hashicorp/hcl/hcl/printer"
	"github.com/spiffe/spire/pkg/agent"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/common/namedpipe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommand_Run(t *testing.T) {
	testTempDir := t.TempDir()
	testDataDir := fmt.Sprintf("%s/data", testTempDir)
	testAgentSocketDir := fmt.Sprintf("%s/spire-agent", testTempDir)

	type fields struct {
		logOptions         []log.Option
		env                *commoncli.Env
		allowUnknownConfig bool
	}
	type args struct {
		args []string
	}
	type want struct {
		returnValue            int
		expectedDataDirCreated bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   want
	}{
		{
			name: "don't create any dir when error loading config",
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
			want: want{
				returnValue:            1,
				expectedDataDirCreated: false,
			},
		},
		{
			name: "create data dir using named pipe",
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
					Stderr: io.Discard,
				},
				allowUnknownConfig: false,
			},
			want: want{
				returnValue:            1,
				expectedDataDirCreated: true,
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			os.RemoveAll(testDataDir)
			os.RemoveAll(testAgentSocketDir)

			cmd := &Command{
				logOptions:         testCase.fields.logOptions,
				env:                testCase.fields.env,
				allowUnknownConfig: testCase.fields.allowUnknownConfig,
			}
			result := cmd.Run(testCase.args.args)

			assert.Equal(t, testCase.want.returnValue, result)
			if testCase.want.expectedDataDirCreated {
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

	// Check for plugins configurations
	pluginConfigs := *c.Plugins
	expectedData := "join_token = \"PLUGIN-AGENT-NOT-A-SECRET\""
	var data bytes.Buffer
	err = printer.DefaultConfig.Fprint(&data, pluginConfigs["plugin_type_agent"]["plugin_name_agent"].PluginData)
	assert.NoError(t, err)

	assert.Len(t, pluginConfigs, 1)
	assert.Len(t, pluginConfigs["plugin_type_agent"], 3)

	pluginConfig := pluginConfigs["plugin_type_agent"]["plugin_name_agent"]
	assert.Nil(t, pluginConfig.Enabled)
	assert.Equal(t, pluginConfig.IsEnabled(), true)
	assert.Equal(t, pluginConfig.PluginChecksum, "pluginAgentChecksum")
	assert.Equal(t, pluginConfig.PluginCmd, "./pluginAgentCmd")
	assert.Equal(t, expectedData, data.String())

	// Disabled plugin
	pluginConfig = pluginConfigs["plugin_type_agent"]["plugin_disabled"]
	assert.NotNil(t, pluginConfig.Enabled)
	assert.Equal(t, pluginConfig.IsEnabled(), false)
	assert.Equal(t, pluginConfig.PluginChecksum, "pluginAgentChecksum")
	assert.Equal(t, pluginConfig.PluginCmd, ".\\pluginAgentCmd")
	assert.Equal(t, expectedData, data.String())

	// Enabled plugin
	pluginConfig = pluginConfigs["plugin_type_agent"]["plugin_enabled"]
	assert.NotNil(t, pluginConfig.Enabled)
	assert.Equal(t, pluginConfig.IsEnabled(), true)
	assert.Equal(t, pluginConfig.PluginChecksum, "pluginAgentChecksum")
	assert.Equal(t, pluginConfig.PluginCmd, "c:/temp/pluginAgentCmd")
	assert.Equal(t, expectedData, data.String())
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
