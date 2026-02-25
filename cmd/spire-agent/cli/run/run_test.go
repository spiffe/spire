package run

import (
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/workloadkey"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mergeInputCase struct {
	msg       string
	fileInput func(*Config)
	cliInput  func(*agentConfig)
	test      func(*testing.T, *Config)
}

type newAgentConfigCase struct {
	msg                string
	expectError        bool
	requireErrorPrefix string
	input              func(*Config)
	logOptions         func(t *testing.T) []log.Option
	test               func(*testing.T, *agent.Config)
}

func TestMergeInput(t *testing.T) {
	cases := []mergeInputCase{
		{
			msg: "data_dir should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.DataDir = "foo"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.DataDir)
			},
		},
		{
			msg:       "data_dir should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *agentConfig) {
				c.DataDir = "foo"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.DataDir)
			},
		},
		{
			msg: "data_dir specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Agent.DataDir = "foo"
			},
			cliInput: func(c *agentConfig) {
				c.DataDir = "bar"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "bar", c.Agent.DataDir)
			},
		},
		{
			msg:       "default_svid_name have a default value of default",
			fileInput: func(c *Config) {},
			cliInput:  func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "default", c.Agent.SDS.DefaultSVIDName)
			},
		},
		{
			msg: "default_svid_name should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.SDS = sdsConfig{
					DefaultSVIDName: "foo",
				}
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.SDS.DefaultSVIDName)
			},
		},
		{
			msg:       "default_bundle_name should default value of ROOTCA",
			fileInput: func(c *Config) {},
			cliInput:  func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "ROOTCA", c.Agent.SDS.DefaultBundleName)
			},
		},
		{
			msg: "default_bundle_name should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.SDS = sdsConfig{
					DefaultBundleName: "foo",
				}
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.SDS.DefaultBundleName)
			},
		},
		{
			msg:       "default_all_bundles_name should default value of ALL",
			fileInput: func(c *Config) {},
			cliInput:  func(ac *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "ALL", c.Agent.SDS.DefaultAllBundlesName)
			},
		},
		{
			msg: "default_all_bundles_name should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.SDS = sdsConfig{
					DefaultAllBundlesName: "foo",
				}
			},
			cliInput: func(ac *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.SDS.DefaultAllBundlesName)
			},
		},
		{
			msg:       "disable_spiffe_cert_validation should default value of false",
			fileInput: func(c *Config) {},
			cliInput:  func(ac *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, false, c.Agent.SDS.DisableSPIFFECertValidation)
			},
		},
		{
			msg: "disable_spiffe_cert_validation should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.SDS = sdsConfig{
					DisableSPIFFECertValidation: true,
				}
			},
			cliInput: func(ac *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, true, c.Agent.SDS.DisableSPIFFECertValidation)
			},
		},
		{
			msg: "insecure_bootstrap should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.InsecureBootstrap = true
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.True(t, c.Agent.InsecureBootstrap)
			},
		},
		{
			msg: "join_token should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.JoinToken = "foo"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.JoinToken)
			},
		},
		{
			msg:       "join_token should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *agentConfig) {
				c.JoinToken = "foo"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.JoinToken)
			},
		},
		{
			msg: "join_token specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Agent.JoinToken = "foo"
			},
			cliInput: func(c *agentConfig) {
				c.JoinToken = "bar"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "bar", c.Agent.JoinToken)
			},
		},
		{
			msg: "join_token_file should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.JoinTokenFile = "foo"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.JoinTokenFile)
			},
		},
		{
			msg:       "join_token_file should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *agentConfig) {
				c.JoinTokenFile = "foo"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.JoinTokenFile)
			},
		},
		{
			msg: "join_token_file specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Agent.JoinTokenFile = "foo"
			},
			cliInput: func(c *agentConfig) {
				c.JoinTokenFile = "bar"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "bar", c.Agent.JoinTokenFile)
			},
		},
		{
			msg: "log_file should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.LogFile = "foo"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.LogFile)
			},
		},
		{
			msg:       "log_file should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *agentConfig) {
				c.LogFile = "foo"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.LogFile)
			},
		},
		{
			msg: "log_file specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Agent.LogFile = "foo"
			},
			cliInput: func(c *agentConfig) {
				c.LogFile = "bar"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "bar", c.Agent.LogFile)
			},
		},
		{
			msg:       "log_format should default to log.DefaultFormat if not set",
			fileInput: func(c *Config) {},
			cliInput:  func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, log.DefaultFormat, c.Agent.LogFormat)
			},
		},
		{
			msg: "log_format should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.LogFormat = "JSON"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "JSON", c.Agent.LogFormat)
			},
		},
		{
			msg:       "log_format should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *agentConfig) {
				c.LogFormat = "JSON"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "JSON", c.Agent.LogFormat)
			},
		},
		{
			msg: "log_format specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Agent.LogFormat = "TEXT"
			},
			cliInput: func(c *agentConfig) {
				c.LogFormat = "JSON"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "JSON", c.Agent.LogFormat)
			},
		},
		{
			msg:       "log_level should default to INFO if not set",
			fileInput: func(c *Config) {},
			cliInput:  func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "INFO", c.Agent.LogLevel)
			},
		},
		{
			msg: "log_level should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.LogLevel = "DEBUG"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "DEBUG", c.Agent.LogLevel)
			},
		},
		{
			msg:       "log_level should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *agentConfig) {
				c.LogLevel = "DEBUG"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "DEBUG", c.Agent.LogLevel)
			},
		},
		{
			msg: "log_level specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Agent.LogLevel = "WARN"
			},
			cliInput: func(c *agentConfig) {
				c.LogLevel = "DEBUG"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "DEBUG", c.Agent.LogLevel)
			},
		},
		{
			msg:       "log_source_location should default to false if not set",
			fileInput: func(c *Config) {},
			cliInput:  func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.False(t, c.Agent.LogSourceLocation)
			},
		},
		{
			msg: "log_source_location should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.LogSourceLocation = true
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.True(t, c.Agent.LogSourceLocation)
			},
		},
		{
			msg:       "log_source_location should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *agentConfig) {
				c.LogSourceLocation = true
			},
			test: func(t *testing.T, c *Config) {
				require.True(t, c.Agent.LogSourceLocation)
			},
		},
		{
			msg: "log_source_location specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Agent.LogSourceLocation = false
			},
			cliInput: func(c *agentConfig) {
				c.LogSourceLocation = true
			},
			test: func(t *testing.T, c *Config) {
				require.True(t, c.Agent.LogSourceLocation)
			},
		},
		{
			msg:       "server_address should not have a default value",
			fileInput: func(c *Config) {},
			cliInput:  func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "", c.Agent.ServerAddress)
			},
		},
		{
			msg: "server_address should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.ServerAddress = "10.0.0.1"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "10.0.0.1", c.Agent.ServerAddress)
			},
		},
		{
			msg:       "server_address should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *agentConfig) {
				c.ServerAddress = "10.0.0.1"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "10.0.0.1", c.Agent.ServerAddress)
			},
		},
		{
			msg: "server_address specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Agent.ServerAddress = "10.0.0.1"
			},
			cliInput: func(c *agentConfig) {
				c.ServerAddress = "10.0.0.2"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "10.0.0.2", c.Agent.ServerAddress)
			},
		},
		{
			msg: "server_port should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.ServerPort = 1337
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, 1337, c.Agent.ServerPort)
			},
		},
		{
			msg:       "server_port should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *agentConfig) {
				c.ServerPort = 1337
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, 1337, c.Agent.ServerPort)
			},
		},
		{
			msg: "server_port specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Agent.ServerPort = 1336
			},
			cliInput: func(c *agentConfig) {
				c.ServerPort = 1337
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, 1337, c.Agent.ServerPort)
			},
		},
		{
			msg: "trust_bundle_path should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.TrustBundlePath = "foo"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.TrustBundlePath)
			},
		},
		{
			msg: "trust_bundle_url should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.TrustBundleURL = "foo"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.TrustBundleURL)
			},
		},
		{
			msg:       "trust_bundle_path should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *agentConfig) {
				c.TrustBundlePath = "foo"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.TrustBundlePath)
			},
		},
		{
			msg: "trust_bundle_path specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Agent.TrustBundlePath = "foo"
			},
			cliInput: func(c *agentConfig) {
				c.TrustBundlePath = "bar"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "bar", c.Agent.TrustBundlePath)
			},
		},
		{
			msg:       "trust_domain should not have a default value",
			fileInput: func(c *Config) {},
			cliInput:  func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "", c.Agent.TrustDomain)
			},
		},
		{
			msg: "trust_domain should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.TrustDomain = "foo"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.TrustDomain)
			},
		},
		{
			// TODO: should it really?
			msg:       "trust_domain should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *agentConfig) {
				c.TrustDomain = "foo"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.TrustDomain)
			},
		},
		{
			msg: "trust_domain specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Agent.TrustDomain = "foo"
			},
			cliInput: func(c *agentConfig) {
				c.TrustDomain = "bar"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "bar", c.Agent.TrustDomain)
			},
		},
		{
			msg: "require_pq_kem should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.Experimental.RequirePQKEM = true
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.True(t, c.Agent.Experimental.RequirePQKEM)
			},
		},
	}
	cases = append(cases, mergeInputCasesOS()...)

	for _, testCase := range cases {
		fileInput := &Config{Agent: &agentConfig{}}
		cliInput := &agentConfig{}

		testCase.fileInput(fileInput)
		testCase.cliInput(cliInput)

		t.Run(testCase.msg, func(t *testing.T) {
			i, err := mergeInput(fileInput, cliInput)
			require.NoError(t, err)

			testCase.test(t, i)
		})
	}
}

func TestNewAgentConfig(t *testing.T) {
	cases := []newAgentConfigCase{
		{
			msg: "server_address and server_port should be correctly parsed",
			input: func(c *Config) {
				c.Agent.ServerAddress = "192.168.1.1"
				c.Agent.ServerPort = 1337
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, "dns:///192.168.1.1:1337", c.ServerAddress)
			},
		},
		{
			msg: "trust_domain should be correctly parsed",
			input: func(c *Config) {
				c.Agent.TrustDomain = "foo"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, "spiffe://foo", c.TrustDomain.IDString())
			},
		},
		{
			msg:         "invalid trust_domain should return an error",
			expectError: true,
			input: func(c *Config) {
				c.Agent.TrustDomain = "i'm invalid"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "insecure_bootstrap should be correctly set to false",
			input: func(c *Config) {
				c.Agent.InsecureBootstrap = false
			},
			test: func(t *testing.T, c *agent.Config) {
				require.False(t, c.TrustBundleSources.GetInsecureBootstrap())
			},
		},
		{
			msg: "insecure_bootstrap should be correctly set to true",
			input: func(c *Config) {
				// in this case, remove trust_bundle_path provided by defaultValidConfig()
				// because trust_bundle_path and insecure_bootstrap cannot be set at the same time
				c.Agent.TrustBundlePath = ""
				c.Agent.InsecureBootstrap = true
			},
			test: func(t *testing.T, c *agent.Config) {
				require.True(t, c.TrustBundleSources.GetInsecureBootstrap())
			},
		},
		{
			msg: "join_token should be correctly configured",
			input: func(c *Config) {
				c.Agent.JoinToken = "foo"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, "foo", c.JoinToken)
			},
		},
		{
			msg:                "join_token and join_token_file cannot both be set",
			expectError:        true,
			requireErrorPrefix: "only one of join_token or join_token_file can be specified, not both",
			input: func(c *Config) {
				c.Agent.JoinToken = "token-value"
				c.Agent.JoinTokenFile = "/path/to/token"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg:                "join_token_file with non-existent file should error",
			expectError:        true,
			requireErrorPrefix: "unable to read join token file",
			input: func(c *Config) {
				c.Agent.JoinTokenFile = "/non/existent/file"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "data_dir should be correctly configured",
			input: func(c *Config) {
				c.Agent.DataDir = "foo"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, "foo", c.DataDir)
			},
		},
		{
			msg: "logger gets set correctly",
			input: func(c *Config) {
				c.Agent.LogLevel = "WARN"
				c.Agent.LogFormat = "TEXT"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.NotNil(t, c.Log)

				l := c.Log.(*log.Logger)
				require.Equal(t, logrus.WarnLevel, l.Level)
				require.IsType(t, &logrus.TextFormatter{}, l.Formatter)
			},
		},
		{
			msg: "log_level and log_format are case insensitive",
			input: func(c *Config) {
				c.Agent.LogLevel = "wArN"
				c.Agent.LogFormat = "TeXt"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.NotNil(t, c.Log)

				l := c.Log.(*log.Logger)
				require.Equal(t, logrus.WarnLevel, l.Level)
				require.IsType(t, &logrus.TextFormatter{}, l.Formatter)
			},
		},
		{
			msg:                "trust_bundle_path and trust_bundle_url cannot both be set",
			expectError:        true,
			requireErrorPrefix: "only one of trust_bundle_url or trust_bundle_path can be specified, not both",
			input: func(c *Config) {
				c.Agent.TrustBundlePath = "foo"
				c.Agent.TrustBundleURL = "foo2"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg:                "insecure_bootstrap and trust_bundle_path cannot both be set",
			expectError:        true,
			requireErrorPrefix: "only one of insecure_bootstrap or trust_bundle_path can be specified, not both",
			input: func(c *Config) {
				c.Agent.TrustBundlePath = "foo"
				c.Agent.InsecureBootstrap = true
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg:                "insecure_bootstrap and trust_bundle_url cannot both be set",
			expectError:        true,
			requireErrorPrefix: "only one of insecure_bootstrap or trust_bundle_url can be specified, not both",
			input: func(c *Config) {
				// in this case, remove trust_bundle_path provided by defaultValidConfig()
				c.Agent.TrustBundlePath = ""
				c.Agent.TrustBundleURL = "foo"
				c.Agent.InsecureBootstrap = true
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg:                "insecure_bootstrap, trust_bundle_url, trust_bundle_path cannot be set at the same time",
			expectError:        true,
			requireErrorPrefix: "only one of insecure_bootstrap, trust_bundle_url, or trust_bundle_path can be specified, not the three options",
			input: func(c *Config) {
				c.Agent.TrustBundlePath = "bar"
				c.Agent.TrustBundleURL = "foo"
				c.Agent.InsecureBootstrap = true
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg:                "trust_bundle_path or trust_bundle_url must be configured unless insecure_bootstrap is set",
			expectError:        true,
			requireErrorPrefix: "trust_bundle_path or trust_bundle_url must be configured unless insecure_bootstrap is set",
			input: func(c *Config) {
				// in this case, remove trust_bundle_path provided by defaultValidConfig()
				c.Agent.TrustBundlePath = ""
				c.Agent.TrustBundleURL = ""
				c.Agent.InsecureBootstrap = false
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg:                "trust_bundle_url must start with https://",
			expectError:        true,
			requireErrorPrefix: "trust bundle URL must start with https://",
			input: func(c *Config) {
				// remove trust_bundle_path provided by defaultValidConfig()
				c.Agent.TrustBundlePath = ""
				c.Agent.TrustBundleURL = "foo.bar"
				c.Agent.InsecureBootstrap = false
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg:                "trust_bundle_url must start with http:// when unix socket",
			expectError:        true,
			requireErrorPrefix: "trust bundle URL must start with http://",
			input: func(c *Config) {
				// remove trust_bundle_path provided by defaultValidConfig()
				c.Agent.TrustBundlePath = ""
				c.Agent.TrustBundleURL = "foo.bar"
				c.Agent.TrustBundleUnixSocket = "foo.bar"
				c.Agent.InsecureBootstrap = false
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg:                "trust_bundle_url query params can not start with spiffe- when unix socket",
			expectError:        true,
			requireErrorPrefix: "trust_bundle_url query params can not start with spiffe-",
			input: func(c *Config) {
				// remove trust_bundle_path provided by defaultValidConfig()
				c.Agent.TrustBundlePath = ""
				c.Agent.TrustBundleURL = "http://localhost/trustbundle?spiffe-test=foo"
				c.Agent.TrustBundleUnixSocket = "foo.bar"
				c.Agent.InsecureBootstrap = false
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg:                "trust_bundle_url query params can not start with spire- when unix socket",
			expectError:        true,
			requireErrorPrefix: "trust_bundle_url query params can not start with spire-",
			input: func(c *Config) {
				// remove trust_bundle_path provided by defaultValidConfig()
				c.Agent.TrustBundlePath = ""
				c.Agent.TrustBundleURL = "http://localhost/trustbundle?spire-test=foo"
				c.Agent.TrustBundleUnixSocket = "foo.bar"
				c.Agent.InsecureBootstrap = false
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "workload_key_type is not set",
			input: func(c *Config) {
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, workloadkey.ECP256, c.WorkloadKeyType)
			},
		},
		{
			msg: "workload_key_type is set",
			input: func(c *Config) {
				c.Agent.WorkloadX509SVIDKeyType = "rsa-2048"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, workloadkey.RSA2048, c.WorkloadKeyType)
			},
		},
		{
			msg:         "workload_key_type invalid value",
			expectError: true,
			input: func(c *Config) {
				c.Agent.WorkloadX509SVIDKeyType = "not a key"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg:         "invalid log_level returns an error",
			expectError: true,
			input: func(c *Config) {
				c.Agent.LogLevel = "not-a-valid-level"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg:         "invalid log_format returns an error",
			expectError: true,
			input: func(c *Config) {
				c.Agent.LogFormat = "not-a-valid-format"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "sync_interval parses a duration",
			input: func(c *Config) {
				c.Agent.Experimental.SyncInterval = "2s45ms"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.EqualValues(t, 2045000000, c.SyncInterval)
			},
		},
		{
			msg:         "invalid sync_interval returns an error",
			expectError: true,
			input: func(c *Config) {
				c.Agent.Experimental.SyncInterval = "moo"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "x509_svid_cache_max_size is set",
			input: func(c *Config) {
				c.Agent.X509SVIDCacheMaxSize = 100
			},
			test: func(t *testing.T, c *agent.Config) {
				require.EqualValues(t, 100, c.X509SVIDCacheMaxSize)
			},
		},
		{
			msg: "x509_svid_cache_max_size is not set",
			input: func(c *Config) {
			},
			test: func(t *testing.T, c *agent.Config) {
				require.EqualValues(t, 0, c.X509SVIDCacheMaxSize)
			},
		},
		{
			msg: "x509_svid_cache_max_size is zero",
			input: func(c *Config) {
				c.Agent.X509SVIDCacheMaxSize = 0
			},
			test: func(t *testing.T, c *agent.Config) {
				require.EqualValues(t, 0, c.X509SVIDCacheMaxSize)
			},
		},
		{
			msg:         "x509_svid_cache_max_size is negative",
			expectError: true,
			input: func(c *Config) {
				c.Agent.X509SVIDCacheMaxSize = -10
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "allowed_foreign_jwt_claims provided",
			input: func(c *Config) {
				c.Agent.AllowedForeignJWTClaims = []string{"c1", "c2"}
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, []string{"c1", "c2"}, c.AllowedForeignJWTClaims)
			},
		},
		{
			msg: "SDS configurables are provided",
			input: func(c *Config) {
				c.Agent.SDS.DefaultSVIDName = "DefaultSVIDName"
				c.Agent.SDS.DefaultBundleName = "DefaultBundleName"
				c.Agent.SDS.DefaultAllBundlesName = "DefaultAllBundlesName"
				c.Agent.SDS.DisableSPIFFECertValidation = true
			},
			test: func(t *testing.T, c *agent.Config) {
				assert.Equal(t, c.DefaultSVIDName, "DefaultSVIDName")
				assert.Equal(t, c.DefaultBundleName, "DefaultBundleName")
				assert.Equal(t, c.DefaultAllBundlesName, "DefaultAllBundlesName")
				assert.True(t, c.DisableSPIFFECertValidation)
			},
		},
		{
			msg: "allowed_foreign_jwt_claims no provided",
			input: func(c *Config) {
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Empty(t, c.AllowedForeignJWTClaims)
			},
		},
		{
			msg: "warn_on_long_trust_domain",
			input: func(c *Config) {
				c.Agent.TrustDomain = strings.Repeat("a", 256)
			},
			logOptions: func(t *testing.T) []log.Option {
				return []log.Option{
					func(logger *log.Logger) error {
						logger.SetOutput(io.Discard)
						hook := test.NewLocal(logger.Logger)
						t.Cleanup(func() {
							spiretest.AssertLogsContainEntries(t, hook.AllEntries(), []spiretest.LogEntry{
								{
									Data:  map[string]any{"trust_domain": strings.Repeat("a", 256)},
									Level: logrus.WarnLevel,
									Message: "Configured trust domain name should be less than 255 characters to be " +
										"SPIFFE compliant; a longer trust domain name may impact interoperability",
								},
							})
						})
						return nil
					},
				}
			},
			test: func(t *testing.T, c *agent.Config) {
				assert.NotNil(t, c)
			},
		},
		{
			msg: "availability_target parses a duration",
			input: func(c *Config) {
				c.Agent.AvailabilityTarget = "24h"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.EqualValues(t, 24*time.Hour, c.AvailabilityTarget)
			},
		},
		{
			msg:         "availability_target is too short",
			expectError: true,
			input: func(c *Config) {
				c.Agent.AvailabilityTarget = "1h"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},

		{
			msg:   "require PQ KEM is disabled (default)",
			input: func(c *Config) {},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, false, c.TLSPolicy.RequirePQKEM)
			},
		},
		{
			msg: "require PQ KEM is enabled",
			input: func(c *Config) {
				c.Agent.Experimental.RequirePQKEM = true
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, true, c.TLSPolicy.RequirePQKEM)
			},
		},
		{
			msg: "jwt_svid_cache_hit_timeout sets the client timeout and logs warning",
			input: func(c *Config) {
				c.Agent.Experimental.JWTSVIDCacheHitTimeout = "10s"
			},
			logOptions: func(t *testing.T) []log.Option {
				return []log.Option{
					func(logger *log.Logger) error {
						logger.SetOutput(io.Discard)
						hook := test.NewLocal(logger.Logger)
						t.Cleanup(func() {
							spiretest.AssertLogsContainEntries(t, hook.AllEntries(), []spiretest.LogEntry{
								{
									Level:   logrus.WarnLevel,
									Message: "The use of 'jwt_svid_cache_hit_timeout' is experimental",
								},
							})
						})
						return nil
					},
				}
			},
			test: func(t *testing.T, ac *agent.Config) {
				require.NotNil(t, ac)
				assert.Equal(t, client.RPCTimeoutWithCacheHit, 10*time.Second)
			},
		},
		{
			msg:                "jwt_svid_cache_hit_timeout returns an error if < 5s",
			expectError:        true,
			requireErrorPrefix: "jwt_svid_cache_hit_timeout (4s) must be greater than 5s",
			input: func(c *Config) {
				c.Agent.Experimental.JWTSVIDCacheHitTimeout = "4s"
			},
			test: func(t *testing.T, ac *agent.Config) {
				require.Nil(t, ac)
			},
		},
		{
			msg:                "jwt_svid_cache_hit_timeout returns an error if >= 30s",
			expectError:        true,
			requireErrorPrefix: "jwt_svid_cache_hit_timeout (30s) must be less than 30s",
			input: func(c *Config) {
				c.Agent.Experimental.JWTSVIDCacheHitTimeout = "30s"
			},
			test: func(t *testing.T, ac *agent.Config) {
				require.Nil(t, ac)
			},
		},
	}
	cases = append(cases, newAgentConfigCasesOS(t)...)
	for _, testCase := range cases {
		input := defaultValidConfig()

		testCase.input(input)

		t.Run(testCase.msg, func(t *testing.T) {
			var logOpts []log.Option
			if testCase.logOptions != nil {
				logOpts = testCase.logOptions(t)
			}

			ac, err := NewAgentConfig(input, logOpts, false)
			if testCase.expectError {
				require.Error(t, err)
				if testCase.requireErrorPrefix != "" {
					spiretest.RequireErrorPrefix(t, err, testCase.requireErrorPrefix)
				}
			} else {
				require.NoError(t, err)
			}

			testCase.test(t, ac)
		})
	}
}

// defaultValidConfig returns the bare minimum config required to
// pass validation etc
func defaultValidConfig() *Config {
	c := defaultConfig()

	c.Agent.DataDir = "."
	c.Agent.ServerAddress = "192.168.1.1"
	c.Agent.ServerPort = 1337
	c.Agent.TrustBundlePath = path.Join(util.ProjectRoot(), "conf/agent/dummy_root_ca.crt")
	c.Agent.TrustDomain = "example.org"

	c.Plugins = &ast.ObjectList{}

	return c
}

func TestWarnOnUnknownConfig(t *testing.T) {
	testFileDir := "../../../../test/fixture/config"

	type logEntry struct {
		section string
		keys    string
	}

	cases := []struct {
		msg                string
		confFile           string
		expectedLogEntries []logEntry
	}{
		{
			msg:      "in root block",
			confFile: "server_and_agent_bad_root_block.conf",
			expectedLogEntries: []logEntry{
				{
					section: "top-level",
					keys:    "unknown_option1,unknown_option2",
				},
			},
		},
		{
			msg:      "in agent block",
			confFile: "agent_bad_agent_block.conf",
			expectedLogEntries: []logEntry{
				{
					section: "agent",
					keys:    "unknown_option1,unknown_option2",
				},
			},
		},
		// TODO: Re-enable unused key detection for telemetry. See
		// https://github.com/spiffe/spire/issues/1101 for more information
		//
		// {
		// 	msg:            "in telemetry block",
		// 	confFile:   "server_and_agent_bad_telemetry_block.conf",
		// 	expectedLogEntries: []logEntry{
		// 		{
		// 			section: "telemetry",
		// 			keys:    "unknown_option1,unknown_option2",
		// 		},
		// 	},
		// },
		{
			msg:      "in nested Prometheus block",
			confFile: "server_and_agent_bad_nested_Prometheus_block.conf",
			expectedLogEntries: []logEntry{
				{
					section: "Prometheus",
					keys:    "unknown_option1,unknown_option2",
				},
			},
		},
		{
			msg:      "in nested DogStatsd block",
			confFile: "server_and_agent_bad_nested_DogStatsd_block.conf",
			expectedLogEntries: []logEntry{
				{
					section: "DogStatsd",
					keys:    "unknown_option1,unknown_option2",
				},
				{
					section: "DogStatsd",
					keys:    "unknown_option3,unknown_option4",
				},
			},
		},
		{
			msg:      "in nested Statsd block",
			confFile: "server_and_agent_bad_nested_Statsd_block.conf",
			expectedLogEntries: []logEntry{
				{
					section: "Statsd",
					keys:    "unknown_option1,unknown_option2",
				},
				{
					section: "Statsd",
					keys:    "unknown_option3,unknown_option4",
				},
			},
		},
		{
			msg:      "in nested M3 block",
			confFile: "server_and_agent_bad_nested_M3_block.conf",
			expectedLogEntries: []logEntry{
				{
					section: "M3",
					keys:    "unknown_option1,unknown_option2",
				},
				{
					section: "M3",
					keys:    "unknown_option3,unknown_option4",
				},
			},
		},
		{
			msg:      "in nested InMem block",
			confFile: "server_and_agent_bad_nested_InMem_block.conf",
			expectedLogEntries: []logEntry{
				{
					section: "InMem",
					keys:    "unknown_option1,unknown_option2",
				},
			},
		},
		{
			msg:      "in nested health_checks block",
			confFile: "server_and_agent_bad_nested_health_checks_block.conf",
			expectedLogEntries: []logEntry{
				{
					section: "health check",
					keys:    "unknown_option1,unknown_option2",
				},
			},
		},
	}

	for _, testCase := range cases {
		c, err := ParseFile(filepath.Join(testFileDir, testCase.confFile), false)
		require.NoError(t, err)

		t.Run(testCase.msg, func(t *testing.T) {
			log, hook := test.NewNullLogger()
			err := checkForUnknownConfig(c, log)
			assert.EqualError(t, err, "unknown configuration detected")

			var logEntries []spiretest.LogEntry
			for _, expectedLogEntry := range testCase.expectedLogEntries {
				logEntries = append(logEntries, spiretest.LogEntry{
					Level:   logrus.ErrorLevel,
					Message: "Unknown configuration detected",
					Data: logrus.Fields{
						"section": expectedLogEntry.section,
						"keys":    expectedLogEntry.keys,
					},
				})
			}
			spiretest.AssertLogsContainEntries(t, hook.AllEntries(), logEntries)
		})
	}
}

func TestJoinTokenFile(t *testing.T) {
	// Test successful join token file reading
	t.Run("join_token_file should be correctly configured", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "join_token_test")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString("test-token-from-file")
		require.NoError(t, err)
		tmpFile.Close()

		input := defaultValidConfig()
		input.Agent.JoinTokenFile = tmpFile.Name()

		ac, err := NewAgentConfig(input, nil, false)
		require.NoError(t, err)
		require.Equal(t, "test-token-from-file", ac.JoinToken)
	})

	// Test whitespace trimming
	t.Run("join_token_file should trim whitespace", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "join_token_test")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString("  \n\t test-token-with-whitespace \t\n  ")
		require.NoError(t, err)
		tmpFile.Close()

		input := defaultValidConfig()
		input.Agent.JoinTokenFile = tmpFile.Name()

		ac, err := NewAgentConfig(input, nil, false)
		require.NoError(t, err)
		require.Equal(t, "test-token-with-whitespace", ac.JoinToken)
	})

	// Test empty file error
	t.Run("join_token_file with empty file should error", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "join_token_test")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())
		tmpFile.Close()

		input := defaultValidConfig()
		input.Agent.JoinTokenFile = tmpFile.Name()

		_, err = NewAgentConfig(input, nil, false)
		require.Error(t, err)
		spiretest.RequireErrorPrefix(t, err, "join token file is empty")
	})

	// Test whitespace-only file error
	t.Run("join_token_file with only whitespace should error", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "join_token_test")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString("  \n\t  \n  ")
		require.NoError(t, err)
		tmpFile.Close()

		input := defaultValidConfig()
		input.Agent.JoinTokenFile = tmpFile.Name()

		_, err = NewAgentConfig(input, nil, false)
		require.Error(t, err)
		spiretest.RequireErrorPrefix(t, err, "join token file is empty")
	})

	// Test non-existent file error
	t.Run("join_token_file with non-existent file should error", func(t *testing.T) {
		input := defaultValidConfig()
		input.Agent.JoinTokenFile = "/non/existent/file"

		_, err := NewAgentConfig(input, nil, false)
		require.Error(t, err)
		spiretest.RequireErrorPrefix(t, err, "unable to read join token file")
	})

	// Test mutual exclusivity with join_token
	t.Run("join_token and join_token_file cannot both be set", func(t *testing.T) {
		input := defaultValidConfig()
		input.Agent.JoinToken = "token-value"
		input.Agent.JoinTokenFile = "/path/to/token"

		_, err := NewAgentConfig(input, nil, false)
		require.Error(t, err)
		spiretest.RequireErrorPrefix(t, err, "only one of join_token or join_token_file can be specified, not both")
	})
}

// TestLogOptions verifies the log options given to NewAgentConfig are applied, and are overridden
// by values from the config file
func TestLogOptions(t *testing.T) {
	fd, err := os.CreateTemp("", "test")
	require.NoError(t, err)
	require.NoError(t, fd.Close())
	defer os.Remove(fd.Name())

	logFile, err := log.NewReopenableFile(fd.Name())
	require.NoError(t, err)
	logOptions := []log.Option{
		log.WithLevel("DEBUG"),
		log.WithFormat(log.JSONFormat),
		log.WithReopenableOutputFile(logFile),
	}

	agentConfig, err := NewAgentConfig(defaultValidConfig(), logOptions, false)
	require.NoError(t, err)

	logger := agentConfig.Log.(*log.Logger).Logger

	// defaultConfig() sets level to info,  which should override DEBUG set above
	require.Equal(t, logrus.InfoLevel, logger.Level)

	// JSON Formatter and output file should be set from above
	require.IsType(t, &logrus.JSONFormatter{}, logger.Formatter)
	require.Equal(t, fd.Name(), logger.Out.(*log.ReopenableFile).Name())
}

func TestExpandEnv(t *testing.T) {
	require.NoError(t, os.Setenv("TEST_DATA_TRUST_DOMAIN", "example.org"))

	cases := []struct {
		expandEnv     bool
		expectedValue string
	}{
		{
			expandEnv:     true,
			expectedValue: "example.org",
		},
		{
			expandEnv:     false,
			expectedValue: "$TEST_DATA_TRUST_DOMAIN",
		},
	}

	for _, testCase := range cases {
		c, err := ParseFile("../../../../test/fixture/config/agent_good_templated.conf", testCase.expandEnv)
		require.NoError(t, err)
		assert.Equal(t, testCase.expectedValue, c.Agent.TrustDomain)
	}
}
