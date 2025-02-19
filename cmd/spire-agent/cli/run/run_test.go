package run

import (
	"io"
	"net/http"
	"net/http/httptest"
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

func TestDownloadTrustBundle(t *testing.T) {
	testTB, _ := os.ReadFile(path.Join(util.ProjectRoot(), "conf/agent/dummy_root_ca.crt"))
	testTBSPIFFE := `{
    "keys": [
        {
            "use": "x509-svid",
            "kty": "EC",
            "crv": "P-384",
            "x": "WjB-nSGSxIYiznb84xu5WGDZj80nL7W1c3zf48Why0ma7Y7mCBKzfQkrgDguI4j0",
            "y": "Z-0_tDH_r8gtOtLLrIpuMwWHoe4vbVBFte1vj6Xt6WeE8lXwcCvLs_mcmvPqVK9j",
            "x5c": [
                "MIIBzDCCAVOgAwIBAgIJAJM4DhRH0vmuMAoGCCqGSM49BAMEMB4xCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZTUElGRkUwHhcNMTgwNTEzMTkzMzQ3WhcNMjMwNTEyMTkzMzQ3WjAeMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGU1BJRkZFMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEWjB+nSGSxIYiznb84xu5WGDZj80nL7W1c3zf48Why0ma7Y7mCBKzfQkrgDguI4j0Z+0/tDH/r8gtOtLLrIpuMwWHoe4vbVBFte1vj6Xt6WeE8lXwcCvLs/mcmvPqVK9jo10wWzAdBgNVHQ4EFgQUh6XzV6LwNazA+GTEVOdu07o5yOgwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwGQYDVR0RBBIwEIYOc3BpZmZlOi8vbG9jYWwwCgYIKoZIzj0EAwQDZwAwZAIwE4Me13qMC9i6Fkx0h26y09QZIbuRqA9puLg9AeeAAyo5tBzRl1YL0KNEp02VKSYJAjBdeJvqjJ9wW55OGj1JQwDFD7kWeEB6oMlwPbI/5hEY3azJi16I0uN1JSYTSWGSqWc="
            ]
        }
    ]
}`

	cases := []struct {
		msg                 string
		status              int
		fileContents        string
		format              string
		expectDownloadError bool
		expectParseError    bool
	}{
		{
			msg:                 "if URL is not found, should be an error",
			status:              http.StatusNotFound,
			fileContents:        "",
			format:              bundleFormatPEM,
			expectDownloadError: true,
			expectParseError:    false,
		},
		{
			msg:                 "if URL returns error 500, should be an error",
			status:              http.StatusInternalServerError,
			fileContents:        "",
			format:              bundleFormatPEM,
			expectDownloadError: true,
			expectParseError:    false,
		},
		{
			msg:                 "if file is not parseable, should be an error",
			status:              http.StatusOK,
			fileContents:        "NON PEM PARSEABLE TEXT HERE",
			format:              bundleFormatPEM,
			expectDownloadError: false,
			expectParseError:    true,
		},
		{
			msg:                 "if file is empty, should be an error",
			status:              http.StatusOK,
			fileContents:        "",
			format:              bundleFormatPEM,
			expectDownloadError: false,
			expectParseError:    true,
		},
		{
			msg:                 "if file is valid, should not be an error",
			status:              http.StatusOK,
			fileContents:        string(testTB),
			format:              bundleFormatPEM,
			expectDownloadError: false,
			expectParseError:    false,
		},
		{
			msg:                 "if file is not parseable, format is SPIFFE, should not be an error",
			status:              http.StatusOK,
			fileContents:        "[}",
			format:              bundleFormatSPIFFE,
			expectDownloadError: false,
			expectParseError:    true,
		},
		{
			msg:                 "if file is valid, format is SPIFFE, should not be an error",
			status:              http.StatusOK,
			fileContents:        testTBSPIFFE,
			format:              bundleFormatSPIFFE,
			expectDownloadError: false,
			expectParseError:    false,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.msg, func(t *testing.T) {
			testServer := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(testCase.status)
					_, _ = io.WriteString(w, testCase.fileContents)
					// if err != nil {
					// 	return
					// }
				}))
			defer testServer.Close()
			bundleBytes, err := downloadTrustBundle(testServer.URL)
			if testCase.expectDownloadError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				_, err := parseTrustBundle(bundleBytes, testCase.format)
				if testCase.expectParseError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
			}
		})
	}
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
				require.False(t, c.InsecureBootstrap)
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
				require.True(t, c.InsecureBootstrap)
			},
		},
		{
			msg: "retry_bootstrap should be correctly set to false",
			input: func(c *Config) {
				c.Agent.RetryBootstrap = false
			},
			test: func(t *testing.T, c *agent.Config) {
				require.False(t, c.RetryBootstrap)
			},
		},
		{
			msg: "retry_bootstrap should be correctly set to true",
			input: func(c *Config) {
				c.Agent.RetryBootstrap = true
			},
			test: func(t *testing.T, c *agent.Config) {
				require.True(t, c.RetryBootstrap)
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
