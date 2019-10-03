package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	minimalRegistrationAPIConfig = `
		domain = "domain.test"
		acme {
			tos_accepted = true
		}
		registration_api {
			socket_path = "/some/socket/path"
		}
`
)

func TestLoadConfig(t *testing.T) {
	require := require.New(t)

	dir, err := ioutil.TempDir("", "")
	require.NoError(err)
	defer os.RemoveAll(dir)

	confPath := filepath.Join(dir, "test.conf")

	_, err = LoadConfig(confPath)
	require.Error(err)
	require.Contains(err.Error(), "unable to load configuration:")

	err = ioutil.WriteFile(confPath, []byte(minimalRegistrationAPIConfig), 0644)
	require.NoError(err)

	config, err := LoadConfig(confPath)
	require.NoError(err)

	require.Equal(&Config{
		LogLevel: defaultLogLevel,
		Domain:   "domain.test",
		ACME: &ACMEConfig{
			ToSAccepted: true,
			CacheDir:    defaultCacheDir,
		},
		RegistrationAPI: &RegistrationAPIConfig{
			SocketPath:   "/some/socket/path",
			PollInterval: defaultPollInterval,
		},
	}, config)
}

func TestParseConfig(t *testing.T) {
	testCases := []struct {
		name string
		in   string
		out  *Config
		err  string
	}{
		{
			name: "malformed HCL",
			in:   `BAD`,
			err:  "unable to decode configuration",
		},
		{
			name: "no domain configured",
			in: `
				acme {
					tos_accepted = true
				}
				registration_api {
					socket_path = "/other/socket/path"
				}
			`,
			err: "domain must be configured",
		},
		{
			name: "no ACME configuration",
			in: `
				domain = "domain.test"
				registration_api {
					socket_path = "/other/socket/path"
				}
			`,
			err: "acme section must be configured",
		},
		{
			name: "ACME ToS not accepted",
			in: `
				domain = "domain.test"
				acme {
				}
				registration_api {
					socket_path = "/other/socket/path"
				}
			`,
			err: "acme.tos_accepted must be set to true",
		},
		{
			name: "ACME overrides",
			in: `
				domain = "domain.test"
				acme {
					tos_accepted = true
					cache_dir = ""
					directory_url = "https://directory.test"
					email = "john@doe.com"
				}
				registration_api {
					socket_path = "/some/socket/path"
				}
			`,
			out: &Config{
				LogLevel: defaultLogLevel,
				Domain:   "domain.test",
				ACME: &ACMEConfig{
					ToSAccepted:  true,
					RawCacheDir:  stringPtr(""),
					CacheDir:     "",
					Email:        "john@doe.com",
					DirectoryURL: "https://directory.test",
				},
				RegistrationAPI: &RegistrationAPIConfig{
					SocketPath:   "/some/socket/path",
					PollInterval: defaultPollInterval,
				},
			},
		},
		{
			name: "both acme and insecure_addr configured",
			in: `
				domain = "domain.test"
				insecure_addr = ":8080"
				acme {
					tos_accepted = true
				}
				registration_api {
					socket_path = "/other/socket/path"
				}
			`,
			err: "insecure_addr and the acme section are mutually exclusive",
		},
		{
			name: "with insecure addr",
			in: `
				domain = "domain.test"
				insecure_addr = ":8080"
				registration_api {
					socket_path = "/some/socket/path"
				}
			`,
			out: &Config{
				LogLevel:     defaultLogLevel,
				Domain:       "domain.test",
				InsecureAddr: ":8080",
				RegistrationAPI: &RegistrationAPIConfig{
					SocketPath:   "/some/socket/path",
					PollInterval: defaultPollInterval,
				},
			},
		},
		{
			name: "no source section configured",
			in: `
				domain = "domain.test"
				acme {
					tos_accepted = true
				}
			`,
			err: "one of registration_api or workload_api section must be configured",
		},
		{
			name: "more than one source section configured",
			in: `
				domain = "domain.test"
				acme {
					tos_accepted = true
				}
				registration_api {}
				workload_api {}
			`,
			err: "registration_api and workload_api sections are mutually exclusive",
		},
		{
			name: "minimal registration API config",
			in:   minimalRegistrationAPIConfig,
			out: &Config{
				LogLevel: defaultLogLevel,
				Domain:   "domain.test",
				ACME: &ACMEConfig{
					ToSAccepted: true,
					CacheDir:    defaultCacheDir,
				},
				RegistrationAPI: &RegistrationAPIConfig{
					SocketPath:   "/some/socket/path",
					PollInterval: defaultPollInterval,
				},
			},
		},
		{
			name: "registration API config overrides",
			in: `
				domain = "domain.test"
				acme {
					tos_accepted = true
				}
				registration_api {
					socket_path = "/other/socket/path"
					poll_interval = "1h"
				}
			`,
			out: &Config{
				LogLevel: defaultLogLevel,
				Domain:   "domain.test",
				ACME: &ACMEConfig{
					ToSAccepted: true,
					CacheDir:    defaultCacheDir,
				},
				RegistrationAPI: &RegistrationAPIConfig{
					SocketPath:      "/other/socket/path",
					PollInterval:    time.Hour,
					RawPollInterval: "1h",
				},
			},
		},
		{
			name: "registration API config missing socket path",
			in: `
				domain = "domain.test"
				acme {
					tos_accepted = true
				}
				registration_api {
				}
			`,
			err: "registration_api.socket_path must be configured",
		},
		{
			name: "registration API config invalid poll interval",
			in: `
				domain = "domain.test"
				acme {
					tos_accepted = true
				}
				registration_api {
					socket_path = "/some/socket/path"
					poll_interval = "huh"
				}
			`,
			err: "invalid registration_api.poll_interval: time: invalid duration huh",
		},
		{
			name: "minimal workload API config",
			in: `
				domain = "domain.test"
				acme {
					tos_accepted = true
				}
				workload_api {
					socket_path = "/some/socket/path"
					trust_domain = "domain.test"
				}
			`,
			out: &Config{
				LogLevel: defaultLogLevel,
				Domain:   "domain.test",
				ACME: &ACMEConfig{
					ToSAccepted: true,
					CacheDir:    defaultCacheDir,
				},
				WorkloadAPI: &WorkloadAPIConfig{
					SocketPath:   "/some/socket/path",
					PollInterval: defaultPollInterval,
					TrustDomain:  "domain.test",
				},
			},
		},
		{
			name: "workload API config overrides",
			in: `
				domain = "domain.test"
				acme {
					tos_accepted = true
				}
				workload_api {
					socket_path = "/other/socket/path"
					poll_interval = "1h"
					trust_domain = "foo.test"
				}
			`,
			out: &Config{
				LogLevel: defaultLogLevel,
				Domain:   "domain.test",
				ACME: &ACMEConfig{
					ToSAccepted: true,
					CacheDir:    defaultCacheDir,
				},
				WorkloadAPI: &WorkloadAPIConfig{
					SocketPath:      "/other/socket/path",
					PollInterval:    time.Hour,
					RawPollInterval: "1h",
					TrustDomain:     "foo.test",
				},
			},
		},
		{
			name: "workload API config missing socket path",
			in: `
				domain = "domain.test"
				acme {
					tos_accepted = true
				}
				workload_api {
					trust_domain = "domain.test"
				}
			`,
			err: "workload_api.socket_path must be configured",
		},
		{
			name: "registration API config invalid poll interval",
			in: `
				domain = "domain.test"
				acme {
					tos_accepted = true
				}
				workload_api {
					socket_path = "/some/socket/path"
					poll_interval = "huh"
					trust_domain = "domain.test"
				}
			`,
			err: "invalid workload_api.poll_interval: time: invalid duration huh",
		},
		{
			name: "workload API config missing trust domain",
			in: `
				domain = "domain.test"
				acme {
					tos_accepted = true
				}
				workload_api {
					socket_path = "/some/socket/path"
				}
			`,
			err: "workload_api.trust_domain must be configured",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual, err := ParseConfig(testCase.in)
			if testCase.err != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), testCase.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.out, actual)
		})
	}
}

func stringPtr(s string) *string {
	return &s
}
