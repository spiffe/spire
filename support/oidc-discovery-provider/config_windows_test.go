//go:build windows

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
			experimental {
				named_pipe_name = "\\name\\for\\server\\api"
			}
		}
`
	minimalEnvServerAPIConfig = `
		domains = ["${SPIFFE_TRUST_DOMAIN}"]
		acme {
			email = "admin@${SPIFFE_TRUST_DOMAIN}"
			tos_accepted = true
		}
		server_api {
			experimental {
				named_pipe_name = "\\name\\for\\server\\api"
			}
		}
`

	serverAPIConfig = &ServerAPIConfig{
		Experimental: experimentalServerAPIConfig{
			NamedPipeName: "\\name\\for\\server\\api",
		},
		PollInterval: defaultPollInterval,
	}
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
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
				}
			`,
			err: "at least one domain must be configured",
		},
		{
			name: "no ACME and serving_cert_file configuration",
			in: `
				domains = ["domain.test"]
				server_api {
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}					
				}
			`,
			err: "either acme, serving_cert_file, insecure_addr or listen_named_pipe_name must be configured",
		},
		{
			name: "ACME ToS not accepted",
			in: `
				domains = ["domain.test"]
				acme {
					email = "admin@domain.test"
				}
				server_api {
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
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
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
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
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
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
					Experimental: experimentalServerAPIConfig{
						NamedPipeName: "\\name\\for\\server\\api",
					},
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
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
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
					Experimental: experimentalServerAPIConfig{
						NamedPipeName: "\\name\\for\\server\\api",
					},
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
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
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
					Experimental: experimentalServerAPIConfig{
						NamedPipeName: "\\name\\for\\server\\api",
					},
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
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
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
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
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
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
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
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
				}
			`,
			err: "insecure_addr and the acme section are mutually exclusive",
		},
		{
			name: "both acme and listen_named_pipe_name configured",
			in: `
				domains = ["domain.test"]
				experimental {
					listen_named_pipe_name = "test"
				}
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				server_api {
					socket_path = "/other/socket/path"
				}
			`,
			err: "listen_named_pipe_name and the acme section are mutually exclusive",
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
			name: "both insecure_addr and listen_named_pipe_name configured",
			in: `
				domains = ["domain.test"]
				insecure_addr = ":8080"
				experimental {
					listen_named_pipe_name = "test"
				}
				server_api {
					socket_path = "/other/socket/path"
				}
			`,
			err: "insecure_addr and listen_named_pipe_name are mutually exclusive",
		},
		{
			name: "with insecure addr and key use",
			in: `
				domains = ["domain.test"]
				insecure_addr = ":8080"
				server_api {
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
				}
				set_key_use = true
			`,
			out: &Config{
				LogLevel:     defaultLogLevel,
				Domains:      []string{"domain.test"},
				InsecureAddr: ":8080",
				ServerAPI: &ServerAPIConfig{
					Experimental: experimentalServerAPIConfig{
						NamedPipeName: "\\name\\for\\server\\api",
					},
					PollInterval: defaultPollInterval,
				},
				SetKeyUse: true,
			},
		},
		{
			name: "with listen_named_pipe_name",
			in: `
				domains = ["domain.test"]
				experimental {
					listen_named_pipe_name = "\\name\\for\\listener"
				}
				server_api {
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
				}
			`,
			out: &Config{
				LogLevel: defaultLogLevel,
				Domains:  []string{"domain.test"},
				Experimental: experimentalConfig{
					ListenNamedPipeName: "\\name\\for\\listener",
				},
				ServerAPI: &ServerAPIConfig{
					Experimental: experimentalServerAPIConfig{
						NamedPipeName: "\\name\\for\\server\\api",
					},
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
				server_api {
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
				}
				workload_api {
					experimental {
						named_pipe_name = "\\name\\for\\workload\\api"
					}
					trust_domain="foo.test"
				}
			`,
			err: "the server_api, workload_api, and file sections are mutually exclusive",
		},
		{
			name: "more than one source section configured",
			in: `
				domains = ["domain.test"]
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				server_api {
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
				}
				file {
					path = "test.spiffe"
				}
			`,
			err: "the server_api, workload_api, and file sections are mutually exclusive",
		},
		{
			name: "more than one source section configured",
			in: `
				domains = ["domain.test"]
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				workload_api {
					experimental {
						named_pipe_name = "\\name\\for\\workload\\api"
					}
					trust_domain="foo.test"
				}
				file {
					path = "test.spiffe"
				}
			`,
			err: "the server_api, workload_api, and file sections are mutually exclusive",
		},
		{
			name: "more than one source section configured",
			in: `
				domains = ["domain.test"]
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
				server_api {
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
				}
				workload_api {
					experimental {
						named_pipe_name = "\\name\\for\\workload\\api"
					}
					trust_domain="foo.test"
				}
				file {
					path = "test.spiffe"
				}
			`,
			err: "the server_api, workload_api, and file sections are mutually exclusive",
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
					Experimental: experimentalServerAPIConfig{
						NamedPipeName: "\\name\\for\\server\\api",
					},
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
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
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
					Experimental: experimentalServerAPIConfig{
						NamedPipeName: "\\name\\for\\server\\api",
					},
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
			err: "named_pipe_name must be configured in the server_api configuration section",
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
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
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
					experimental {
						named_pipe_name = "\\name\\for\\workload\\api"
					}
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
					Experimental: experimentalWorkloadAPIConfig{
						NamedPipeName: "\\name\\for\\workload\\api",
					},
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
					experimental {
						named_pipe_name = "\\name\\for\\workload\\api"
					}
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
					Experimental: experimentalWorkloadAPIConfig{
						NamedPipeName: "\\name\\for\\workload\\api",
					},
					PollInterval:    time.Hour,
					RawPollInterval: "1h",
					TrustDomain:     "foo.test",
				},
			},
		},
		{
			name: "workload API config missing named pipe name",
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
			err: "named_pipe_name must be configured in the workload_api configuration section",
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
					experimental {
						named_pipe_name = "\\name\\for\\workload\\api"
					}
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
					experimental {
						named_pipe_name = "\\name\\for\\workload\\api"
					}					
				}
			`,
			err: "trust_domain must be configured in the workload_api configuration section",
		},
		{
			name: "with JWT issuer",
			in: `
				domains = ["domain.test"]
				jwt_issuer = "https://domain.test/some/issuer/path/issuer1/"
				serving_cert_file {
					cert_file_path = "test"
					key_file_path = "test"
				}
				server_api {
					address = "unix:///some/socket/path"
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
				}
			`,
			out: &Config{
				LogLevel:  defaultLogLevel,
				Domains:   []string{"domain.test"},
				JWTIssuer: "https://domain.test/some/issuer/path/issuer1/",
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
					Experimental: experimentalServerAPIConfig{
						NamedPipeName: "\\name\\for\\server\\api",
					},
				},
				HealthChecks: nil,
			},
		},
		{
			name: "JWT issuer with missing scheme",
			in: `
				domains = ["domain.test"]
				jwt_issuer = "domain.test/some/issuer/path/issuer1/"
				serving_cert_file {
					cert_file_path = "test"
					key_file_path = "test"
				}
				server_api {
					address = "unix:///some/socket/path"
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
				}
			`,
			err: "the jwt_issuer url must contain a scheme",
		},
		{
			name: "JWT issuer with missing host",
			in: `
				domains = ["domain.test"]
				jwt_issuer = "https:///path"
				serving_cert_file {
					cert_file_path = "test"
					key_file_path = "test"
				}
				server_api {
					address = "unix:///some/socket/path"
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
				}
			`,
			err: "the jwt_issuer url must contain a host",
		},
		{
			name: "JWT issuer is invalid",
			in: `
				domains = ["domain.test"]
				jwt_issuer = "http://domain.test:someportnumber/some/path"
				serving_cert_file {
					cert_file_path = "test"
					key_file_path = "test"
				}
				server_api {
					address = "unix:///some/socket/path"
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
				}
			`,
			err: "the jwt_issuer url could not be parsed",
		},
		{
			name: "JWT issuer is empty",
			in: `
				domains = ["domain.test"]
				jwt_issuer = ""
				serving_cert_file {
					cert_file_path = "test"
					key_file_path = "test"
				}
				server_api {
					address = "unix:///some/socket/path"
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}
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
					Experimental: experimentalServerAPIConfig{
						NamedPipeName: "\\name\\for\\server\\api",
					},
				},
				HealthChecks: nil,
			},
		},
	}
}
