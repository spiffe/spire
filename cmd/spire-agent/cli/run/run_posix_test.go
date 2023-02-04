//go:build !windows
// +build !windows

package run

import (
	"bytes"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/spiffe/spire/pkg/agent"
	"github.com/spiffe/spire/pkg/common/catalog"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/fflag"
	"github.com/spiffe/spire/pkg/common/log"
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
		code               int
		dataDirCreated     bool
		agentUdsDirCreated bool
		stderrContent      string
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
				code:               1,
				agentUdsDirCreated: false,
				dataDirCreated:     false,
				stderrContent:      "could not find config file",
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
			want: want{
				code:               1,
				agentUdsDirCreated: false,
				dataDirCreated:     false,
				stderrContent:      "flag provided but not defined: -namedPipeName",
			},
		},
		{
			name: "creates spire-agent uds and data dirs",
			args: args{
				args: []string{
					"-config", "../../../../test/fixture/config/agent_run_posix.conf",
					"-trustBundle", "../../../../conf/agent/dummy_root_ca.crt",
					"-dataDir", testDataDir,
					"-socketPath", fmt.Sprintf("%s/spire-agent/api.sock", testTempDir),
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
				code:               1,
				agentUdsDirCreated: true,
				dataDirCreated:     true,
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
			if testCase.want.agentUdsDirCreated {
				assert.DirExistsf(t, testAgentSocketDir, "spire-agent uds dir should be created")
				currentUmask := syscall.Umask(0)
				assert.Equalf(t, currentUmask, 0027, "spire-agent process should be created with 0027 umask")
			} else {
				assert.NoDirExistsf(t, testAgentSocketDir, "spire-agent uds dir should not be created")
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
		"-socketPath=/tmp/spire-agent/public/api.sock",
		"-trustBundle=conf/agent/dummy_root_ca.crt",
		"-trustBundleUrl=https://test.url",
		"-trustDomain=example.org",
		"-allowUnauthenticatedVerifiers",
	}, os.Stderr)
	require.NoError(t, err)
	assert.Equal(t, c.DataDir, ".")
	assert.Equal(t, c.LogLevel, "INFO")
	assert.Equal(t, c.ServerAddress, "127.0.0.1")
	assert.Equal(t, c.ServerPort, 8081)
	assert.Equal(t, c.SocketPath, "/tmp/spire-agent/public/api.sock")
	assert.Equal(t, c.TrustBundlePath, "conf/agent/dummy_root_ca.crt")
	assert.Equal(t, c.TrustBundleURL, "https://test.url")
	assert.Equal(t, c.TrustDomain, "example.org")
	assert.Equal(t, c.AllowUnauthenticatedVerifiers, true)
}

func TestParseConfigGood(t *testing.T) {
	c, err := ParseFile("../../../../test/fixture/config/agent_good_posix.conf", false)
	require.NoError(t, err)
	assert.Equal(t, ".", c.Agent.DataDir)
	assert.Equal(t, "INFO", c.Agent.LogLevel)
	assert.Equal(t, "127.0.0.1", c.Agent.ServerAddress)
	assert.Equal(t, 8081, c.Agent.ServerPort)
	assert.Equal(t, "/tmp/spire-agent/public/api.sock", c.Agent.SocketPath)
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
			Path:     "./pluginAgentCmd",
			Checksum: "pluginAgentChecksum",
			Data:     data,
			Disabled: true,
		},
		{
			Type:     "plugin_type_agent",
			Name:     "plugin_enabled",
			Path:     "./pluginAgentCmd",
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
			msg:       "socket_path should default to /tmp/spire-agent/public/api.sock if not set",
			fileInput: func(c *Config) {},
			cliInput:  func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "/tmp/spire-agent/public/api.sock", c.Agent.SocketPath)
			},
		},
		{
			msg: "socket_path should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.SocketPath = "foo"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.SocketPath)
			},
		},
		{
			msg:       "socket_path should be configuable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *agentConfig) {
				c.SocketPath = "foo"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.SocketPath)
			},
		},
		{
			msg: "socket_path specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Agent.SocketPath = "foo"
			},
			cliInput: func(c *agentConfig) {
				c.SocketPath = "bar"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "bar", c.Agent.SocketPath)
			},
		},
		{
			msg: "admin_socket_path should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.AdminSocketPath = "/tmp/admin.sock"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "/tmp/admin.sock", c.Agent.AdminSocketPath)
			},
		},
	}
}

func newAgentConfigCasesOS() []newAgentConfigCase {
	return []newAgentConfigCase{
		{
			msg: "socket_path should be correctly configured",
			input: func(c *Config) {
				c.Agent.SocketPath = "/foo"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, "/foo", c.BindAddress.String())
				require.Equal(t, "unix", c.BindAddress.Network())
			},
		},
		{
			msg: "admin_socket_path should be correctly configured",
			input: func(c *Config) {
				c.Agent.AdminSocketPath = "/foo"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, "/foo", c.AdminBindAddress.String())
				require.Equal(t, "unix", c.AdminBindAddress.Network())
			},
		},
		{
			msg: "admin_socket_path configured with similar folder that socket_path",
			input: func(c *Config) {
				c.Agent.SocketPath = "/tmp/workload/workload.sock"
				c.Agent.AdminSocketPath = "/tmp/workload-admin/admin.sock"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, "/tmp/workload-admin/admin.sock", c.AdminBindAddress.String())
				require.Equal(t, "unix", c.AdminBindAddress.Network())
			},
		},
		{
			msg: "admin_socket_path should be correctly configured in different folder",
			input: func(c *Config) {
				c.Agent.SocketPath = "/tmp/workload/workload.sock"
				c.Agent.AdminSocketPath = "/tmp/admin.sock"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, "/tmp/workload/workload.sock", c.BindAddress.String())
				require.Equal(t, "unix", c.BindAddress.Network())
				require.Equal(t, "/tmp/admin.sock", c.AdminBindAddress.String())
				require.Equal(t, "unix", c.AdminBindAddress.Network())
			},
		},
		{
			msg:         "admin_socket_path same folder as socket_path",
			expectError: true,
			input: func(c *Config) {
				c.Agent.SocketPath = "/tmp/workload.sock"
				c.Agent.AdminSocketPath = "/tmp/admin.sock"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg:         "admin_socket_path configured with subfolder socket_path",
			expectError: true,
			input: func(c *Config) {
				c.Agent.SocketPath = "/tmp/workload.sock"
				c.Agent.AdminSocketPath = "/tmp/admin/admin.sock"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg:         "admin_socket_path relative folder",
			expectError: true,
			input: func(c *Config) {
				c.Agent.SocketPath = "./sock/workload.sock"
				c.Agent.AdminSocketPath = "./sock/admin.sock"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "admin_socket_path not provided",
			input: func(c *Config) {
				c.Agent.AdminSocketPath = ""
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c.AdminBindAddress)
			},
		},
	}
}
