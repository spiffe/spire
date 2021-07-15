package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

var (
	minimalServerAPIConfig = `
		domain = "domain.test"
		acme {
			email = "admin@domain.test"
			tos_accepted = true
		}
		server_api {
			address = "unix:///some/socket/path"
		}
`
)

func TestLoadConfig(t *testing.T) {
	require := require.New(t)

	dir := spiretest.TempDir(t)

	confPath := filepath.Join(dir, "test.conf")

	_, err := LoadConfig(confPath)
	require.Error(err)
	require.Contains(err.Error(), "unable to load configuration:")

	err = os.WriteFile(confPath, []byte(minimalServerAPIConfig), 0600)
	require.NoError(err)

	config, err := LoadConfig(confPath)
	require.NoError(err)

	require.Equal(&Config{
		LogLevel: defaultLogLevel,
		Domain:   "domain.test",
		ACME: &ACMEConfig{
			CacheDir:    defaultCacheDir,
			Email:       "admin@domain.test",
			ToSAccepted: true,
		},
		ServerAPI: &ServerAPIConfig{
			Address:      "unix:///some/socket/path",
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
					email = "admin@domain.test"
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
			err: "either acme or listen_socket_path must be configured",
		},
		{
			name: "ACME ToS not accepted",
			in: `
				domain = "domain.test"
				acme {
					email = "admin@domain.test"
				}
				registration_api {
					socket_path = "/other/socket/path"
				}
			`,
			err: "tos_accepted must be set to true in the acme configuration section",
		},
		{
			name: "ACME email not configured",
			in: `
				domain = "domain.test"
				acme {
					tos_accepted = true
				}
				registration_api {
					socket_path = "/other/socket/path"
				}
			`,
			err: "email must be configured in the acme configuration section",
		},
		{
			name: "ACME overrides",
			in: `
				domain = "domain.test"
				acme {
					tos_accepted = true
					cache_dir = ""
					directory_url = "https://directory.test"
					email = "admin@domain.test"
				}
				registration_api {
					socket_path = "/some/socket/path"
				}
			`,
			out: &Config{
				LogLevel: defaultLogLevel,
				Domain:   "domain.test",
				ACME: &ACMEConfig{
					CacheDir:     "",
					Email:        "admin@domain.test",
					DirectoryURL: "https://directory.test",
					RawCacheDir:  stringPtr(""),
					ToSAccepted:  true,
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
					email = "admin@domain.test"
					tos_accepted = true
				}
				registration_api {
					socket_path = "/other/socket/path"
				}
			`,
			err: "insecure_addr and the acme section are mutually exclusive",
		},
		{
			name: "both acme and socket_listen_path configured",
			in: `
				domain = "domain.test"
				listen_socket_path = "test"
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				registration_api {
					socket_path = "/other/socket/path"
				}
			`,
			err: "listen_socket_path and the acme section are mutually exclusive",
		},
		{
			name: "both insecure_addr and socket_listen_path configured",
			in: `
				domain = "domain.test"
				insecure_addr = ":8080"
				listen_socket_path = "test"
				registration_api {
					socket_path = "/other/socket/path"
				}
			`,
			err: "insecure_addr and listen_socket_path are mutually exclusive",
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
			name: "with listen_socket_path",
			in: `
				domain = "domain.test"
				listen_socket_path = "/a/path/here"
				registration_api {
					socket_path = "/some/socket/path"
				}
			`,
			out: &Config{
				LogLevel:         defaultLogLevel,
				Domain:           "domain.test",
				ListenSocketPath: "/a/path/here",
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
					email = "admin@domain.test"
					tos_accepted = true
				}
			`,
			err: "either the server_api or workload_api section must be configured",
		},
		{
			name: "more than one source section configured",
			in: `
				domain = "domain.test"
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				server_api { address = "unix:///some/socket/path" }
				workload_api { socket_path = "/some/socket/path" trust_domain="foo.test" }
			`,
			err: "the server_api, workload_api, and deprecated registration_api sections are mutually exclusive",
		},

		{
			name: "minimal server API config",
			in:   minimalServerAPIConfig,
			out: &Config{
				LogLevel: defaultLogLevel,
				Domain:   "domain.test",
				ACME: &ACMEConfig{
					CacheDir:    defaultCacheDir,
					Email:       "admin@domain.test",
					ToSAccepted: true,
				},
				ServerAPI: &ServerAPIConfig{
					Address:      "unix:///some/socket/path",
					PollInterval: defaultPollInterval,
				},
			},
		},
		{
			name: "server API config overrides",
			in: `
				domain = "domain.test"
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				server_api {
					address = "unix:///other/socket/path"
					poll_interval = "1h"
				}
			`,
			out: &Config{
				LogLevel: defaultLogLevel,
				Domain:   "domain.test",
				ACME: &ACMEConfig{
					CacheDir:    defaultCacheDir,
					Email:       "admin@domain.test",
					ToSAccepted: true,
				},
				ServerAPI: &ServerAPIConfig{
					Address:         "unix:///other/socket/path",
					PollInterval:    time.Hour,
					RawPollInterval: "1h",
				},
			},
		},
		{
			name: "server API config missing address",
			in: `
				domain = "domain.test"
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				server_api {
				}
			`,
			err: "address must be configured in the server_api configuration section",
		},
		{
			name: "server API config invalid address",
			in: `
				domain = "domain.test"
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				server_api {
					address = "localhost:8199"
				}
			`,
			err: "address must use the unix name system in the server_api configuration section",
		},
		{
			name: "server API config invalid poll interval",
			in: `
				domain = "domain.test"
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				server_api {
					address = "unix:///some/socket/path"
					poll_interval = "huh"
				}
			`,
			err: "invalid poll_interval in the server_api configuration section: time: invalid duration \"huh\"",
		},

		{
			name: "minimal registration API config",
			in: `
				domain = "domain.test"
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				registration_api {
					socket_path = "/some/socket/path"
				}
			`,
			out: &Config{
				LogLevel: defaultLogLevel,
				Domain:   "domain.test",
				ACME: &ACMEConfig{
					CacheDir:    defaultCacheDir,
					Email:       "admin@domain.test",
					ToSAccepted: true,
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
					email = "admin@domain.test"
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
					CacheDir:    defaultCacheDir,
					Email:       "admin@domain.test",
					ToSAccepted: true,
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
					email = "admin@domain.test"
					tos_accepted = true
				}
				registration_api {
				}
			`,
			err: "socket_path must be configured in the registration_api configuration section",
		},
		{
			name: "registration API config invalid poll interval",
			in: `
				domain = "domain.test"
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				registration_api {
					socket_path = "/some/socket/path"
					poll_interval = "huh"
				}
			`,
			err: "invalid poll_interval in the registration_api configuration section: time: invalid duration \"huh\"",
		},
		{
			name: "minimal workload API config",
			in: `
				domain = "domain.test"
				acme {
					email = "admin@domain.test"
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
					CacheDir:    defaultCacheDir,
					Email:       "admin@domain.test",
					ToSAccepted: true,
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
					email = "admin@domain.test"
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
					CacheDir:    defaultCacheDir,
					Email:       "admin@domain.test",
					ToSAccepted: true,
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
					email = "admin@domain.test"
					tos_accepted = true
				}
				workload_api {
					trust_domain = "domain.test"
				}
			`,
			err: "socket_path must be configured in the workload_api configuration section",
		},
		{
			name: "registration API config invalid poll interval",
			in: `
				domain = "domain.test"
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				workload_api {
					socket_path = "/some/socket/path"
					poll_interval = "huh"
					trust_domain = "domain.test"
				}
			`,
			err: "invalid poll_interval in the workload_api configuration section: time: invalid duration \"huh\"",
		},
		{
			name: "workload API config missing trust domain",
			in: `
				domain = "domain.test"
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				workload_api {
					socket_path = "/some/socket/path"
				}
			`,
			err: "trust_domain must be configured in the workload_api configuration section",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
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
