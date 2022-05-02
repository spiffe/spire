//go:build windows
// +build windows

package main

import "time"

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
			name: "no ACME configuration",
			in: `
				domains = ["domain.test"]
				server_api {
					experimental {
						named_pipe_name = "\\name\\for\\server\\api"
					}					
				}
			`,
			err: "either acme or listen_named_pipe_name must be configured",
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
	}
}
