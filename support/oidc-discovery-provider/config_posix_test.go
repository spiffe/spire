//go:build !windows
// +build !windows

package main

import (
	"net"
	"time"
)

var (
	minimalServerAPIConfig = `
		domains = ["domain.test"]
		acme {
			email = "admin@domain.test"
			tos_accepted = true
		}
		server_api {
			address = "unix:///some/socket/path"
		}
`

	serverAPIConfig = &ServerAPIConfig{
		Address:      "unix:///some/socket/path",
		PollInterval: defaultPollInterval,
	}

	fileDontExistMessage = "no such file or directory"
)

func parseConfigCasesOS() []parseConfigCase {
	return []parseConfigCase{
		{
			name: "no domain configured",
			in: `
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				server_api {
					socket_path = "/other/socket/path"
				}
			`,
			err: "at least one domain must be configured",
		},
		{
			name: "no ACME and serving_cert_file configuration",
			in: `
				domains = ["domain.test"]
				server_api {
					socket_path = "/other/socket/path"
				}
			`,
			err: "either acme, serving_cert_file, insecure_addr or listen_socket_path must be configured",
		},
		{
			name: "ACME ToS not accepted",
			in: `
				domains = ["domain.test"]
				acme {
					email = "admin@domain.test"
				}
				server_api {
					socket_path = "/other/socket/path"
				}
			`,
			err: "tos_accepted must be set to true in the acme configuration section",
		},
		{
			name: "ACME email not configured",
			in: `
				domains = ["domain.test"]
				acme {
					tos_accepted = true
				}
				server_api {
					socket_path = "/other/socket/path"
				}
			`,
			err: "email must be configured in the acme configuration section",
		},
		{
			name: "ACME overrides",
			in: `
				domains = ["domain.test"]
				acme {
					tos_accepted = true
					cache_dir = ""
					directory_url = "https://directory.test"
					email = "admin@domain.test"
				}
				server_api {
					address = "unix:///some/socket/path"
				}
			`,
			out: &Config{
				LogLevel: defaultLogLevel,
				Domains:  []string{"domain.test"},
				ACME: &ACMEConfig{
					CacheDir:     "",
					Email:        "admin@domain.test",
					DirectoryURL: "https://directory.test",
					RawCacheDir:  stringPtr(""),
					ToSAccepted:  true,
				},
				ServerAPI: &ServerAPIConfig{
					Address:      "unix:///some/socket/path",
					PollInterval: defaultPollInterval,
				},
			},
		},
		{
			name: "serving_cert_file configuration with defaults",
			in: `
				domains = ["domain.test"]
				serving_cert_file {
					cert_file_path = "test"
					key_file_path = "test"
				}
				server_api {
					address = "unix:///some/socket/path"
				}
			`,
			out: &Config{
				LogLevel: defaultLogLevel,
				Domains:  []string{"domain.test"},
				ServingCertFile: &ServingCertFileConfig{
					CertFilePath:     "test",
					KeyFilePath:      "test",
					FileSyncInterval: time.Minute,
					Addr: &net.TCPAddr{
						IP:   nil,
						Port: 443,
					},
					RawAddr: ":443",
				},
				ServerAPI: &ServerAPIConfig{
					Address:      "unix:///some/socket/path",
					PollInterval: defaultPollInterval,
				},
			},
		},
		{
			name: "serving_cert_file configuration with optionals",
			in: `
				domains = ["domain.test"]
				serving_cert_file {
					cert_file_path = "test"
					key_file_path = "test"
					file_sync_interval = "5m"
					addr = "127.0.0.1:9090"
				}
				server_api {
					address = "unix:///some/socket/path"
				}
			`,
			out: &Config{
				LogLevel: defaultLogLevel,
				Domains:  []string{"domain.test"},
				ServingCertFile: &ServingCertFileConfig{
					CertFilePath:        "test",
					KeyFilePath:         "test",
					FileSyncInterval:    5 * time.Minute,
					RawFileSyncInterval: "5m",
					Addr: &net.TCPAddr{
						IP:   net.ParseIP("127.0.0.1"),
						Port: 9090,
					},
					RawAddr: "127.0.0.1:9090",
				},
				ServerAPI: &ServerAPIConfig{
					Address:      "unix:///some/socket/path",
					PollInterval: defaultPollInterval,
				},
			},
		},
		{
			name: "serving_cert_file configuration without cert_file_path",
			in: `
				domains = ["domain.test"]
				serving_cert_file {
					key_file_path = "test"
				}
				server_api {
					address = "unix:///some/socket/path"
				}
			`,
			err: "cert_file_path must be configured in the serving_cert_file configuration section",
		},
		{
			name: "serving_cert_file configuration without key_file_path",
			in: `
				domains = ["domain.test"]
				serving_cert_file {
					cert_file_path = "test"
				}
				server_api {
					address = "unix:///some/socket/path"
				}
			`,
			err: "key_file_path must be configured in the serving_cert_file configuration section",
		},
		{
			name: "serving_cert_file configuration with invalid addr",
			in: `
				domains = ["domain.test"]
				serving_cert_file {
					cert_file_path = "test"
					key_file_path = "test"
					addr = "127.0.0.1.1:9090"
				}
				server_api {
					address = "unix:///some/socket/path"
				}
			`,
			err: "invalid addr in the serving_cert_file configuration section: lookup 127.0.0.1.1: no such host",
		},
		{
			name: "both acme and insecure_addr configured",
			in: `
				domains = ["domain.test"]
				insecure_addr = ":8080"
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				server_api {
					socket_path = "/other/socket/path"
				}
			`,
			err: "insecure_addr and the acme section are mutually exclusive",
		},
		{
			name: "both acme and socket_listen_path configured",
			in: `
				domains = ["domain.test"]
				listen_socket_path = "test"
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				server_api {
					socket_path = "/other/socket/path"
				}
			`,
			err: "listen_socket_path and the acme section are mutually exclusive",
		},
		{
			name: "both acme and serving_cert_file configured",
			in: `
				domains = ["domain.test"]
				serving_cert_file {
					cert_file_path = "test"
					key_file_path = "test"
				}
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				server_api {
					socket_path = "/other/socket/path"
				}
			`,
			err: "acme and serving_cert_file are mutually exclusive",
		},
		{
			name: "both insecure_addr and socket_listen_path configured",
			in: `
				domains = ["domain.test"]
				insecure_addr = ":8080"
				listen_socket_path = "test"
				server_api {
					socket_path = "/other/socket/path"
				}
			`,
			err: "insecure_addr and listen_socket_path are mutually exclusive",
		},
		{
			name: "both insecure_addr and serving_cert_file configured",
			in: `
				domains = ["domain.test"]
				insecure_addr = ":8080"
				serving_cert_file {
					cert_file_path = "test"
					key_file_path = "test"
				}
				server_api {
					socket_path = "/other/socket/path"
				}
			`,
			err: "serving_cert_file and insecure_addr are mutually exclusive",
		},
		{
			name: "both serving_cert_file and socket_listen_path configured",
			in: `
				domains = ["domain.test"]
				serving_cert_file {
					cert_file_path = "test"
					key_file_path = "test"
				}
				listen_socket_path = "test"
				server_api {
					socket_path = "/other/socket/path"
				}
			`,
			err: "serving_cert_file and listen_socket_path are mutually exclusive",
		},
		{
			name: "with insecure addr and key use",
			in: `
				domains = ["domain.test"]
				insecure_addr = ":8080"
				server_api {
					address = "unix:///some/socket/path"
				}
				set_key_use = true
			`,
			out: &Config{
				LogLevel:     defaultLogLevel,
				Domains:      []string{"domain.test"},
				InsecureAddr: ":8080",
				ServerAPI: &ServerAPIConfig{
					Address:      "unix:///some/socket/path",
					PollInterval: defaultPollInterval,
				},
				SetKeyUse: true,
			},
		},
		{
			name: "with listen_socket_path",
			in: `
				domains = ["domain.test"]
				listen_socket_path = "/a/path/here"
				server_api {
					address = "unix:///some/socket/path"
				}
			`,
			out: &Config{
				LogLevel:         defaultLogLevel,
				Domains:          []string{"domain.test"},
				ListenSocketPath: "/a/path/here",
				ServerAPI: &ServerAPIConfig{
					Address:      "unix:///some/socket/path",
					PollInterval: defaultPollInterval,
				},
			},
		},
		{
			name: "more than one source section configured",
			in: `
				domains = ["domain.test"]
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				server_api { address = "unix:///some/socket/path" }
				workload_api { socket_path = "/some/socket/path" trust_domain="foo.test" }
			`,
			err: "the server_api and workload_api sections are mutually exclusive",
		},
		{
			name: "minimal server API config",
			in:   minimalServerAPIConfig,
			out: &Config{
				LogLevel: defaultLogLevel,
				Domains:  []string{"domain.test"},
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
				domains = ["domain.test"]
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
				Domains:  []string{"domain.test"},
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
				domains = ["domain.test"]
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
				domains = ["domain.test"]
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
				domains = ["domain.test"]
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
			name: "minimal workload API config",
			in: `
				domains = ["domain.test"]
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
				Domains:  []string{"domain.test"},
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
				domains = ["domain.test"]
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
				Domains:  []string{"domain.test"},
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
				domains = ["domain.test"]
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
			name: "workload API config invalid poll interval",
			in: `
				domains = ["domain.test"]
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
				domains = ["domain.test"]
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
		{
			name: "health checks default values",
			in: `
				domains = ["domain.test"]
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				server_api {
					address = "unix:///some/socket/path"
				}
				health_checks {}
			`,
			out: &Config{
				LogLevel: defaultLogLevel,
				Domains:  []string{"domain.test"},
				ACME: &ACMEConfig{
					CacheDir:    defaultCacheDir,
					Email:       "admin@domain.test",
					ToSAccepted: true,
				},
				ServerAPI: &ServerAPIConfig{
					Address:      "unix:///some/socket/path",
					PollInterval: defaultPollInterval,
				},
				HealthChecks: &HealthChecksConfig{
					BindPort:  defaultHealthChecksBindPort,
					ReadyPath: defaultHealthChecksReadyPath,
					LivePath:  defaultHealthChecksLivePath,
				},
			},
		},
		{
			name: "health checks config overrides",
			in: `
				domains = ["domain.test"]
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				server_api {
					address = "unix:///some/socket/path"
				}
				health_checks {
					bind_address = "127.0.0.1"
					bind_port = "8888"
					live_path = "/live/override"
					ready_path = "/ready/override"
				}
			`,
			out: &Config{
				LogLevel: defaultLogLevel,
				Domains:  []string{"domain.test"},
				ACME: &ACMEConfig{
					CacheDir:    defaultCacheDir,
					Email:       "admin@domain.test",
					ToSAccepted: true,
				},
				ServerAPI: &ServerAPIConfig{
					Address:      "unix:///some/socket/path",
					PollInterval: defaultPollInterval,
				},
				HealthChecks: &HealthChecksConfig{
					BindPort:  8888,
					LivePath:  "/live/override",
					ReadyPath: "/ready/override",
				},
			},
		},
		{
			name: "health checks disabled",
			in: `
				domains = ["domain.test"]
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				server_api {
					address = "unix:///some/socket/path"
				}
			`,
			out: &Config{
				LogLevel: defaultLogLevel,
				Domains:  []string{"domain.test"},
				ACME: &ACMEConfig{
					CacheDir:    defaultCacheDir,
					Email:       "admin@domain.test",
					ToSAccepted: true,
				},
				ServerAPI: &ServerAPIConfig{
					Address:      "unix:///some/socket/path",
					PollInterval: defaultPollInterval,
				},
				HealthChecks: nil,
			},
		},
	}
}
