package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	testMinimalConfig = `
		trust_domain = "TRUSTDOMAIN"
		cluster = "CLUSTER"
		server_socket_path = "SOCKETPATH"
`
)

func TestLoadConfig(t *testing.T) {
	require := require.New(t)

	dir, err := ioutil.TempDir("", "spire-adm-webhook-config-")
	require.NoError(err)
	defer os.RemoveAll(dir)

	confPath := filepath.Join(dir, "test.conf")

	_, err = LoadConfig(confPath)
	require.Error(err)
	require.Contains(err.Error(), "unable to load configuration:")

	err = ioutil.WriteFile(confPath, []byte(testMinimalConfig), 0644)
	require.NoError(err)

	config, err := LoadConfig(confPath)
	require.NoError(err)

	require.Equal(&Config{
		Log: LogConfig{
			Level: defaultLogLevel,
		},
		Addr:             ":8443",
		CertPath:         defaultCertPath,
		KeyPath:          defaultKeyPath,
		ServerSocketPath: "SOCKETPATH",
		TrustDomain:      "TRUSTDOMAIN",
		Cluster:          "CLUSTER",
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
			name: "defaults",
			in:   testMinimalConfig,
			out: &Config{
				Log: LogConfig{
					Level: defaultLogLevel,
				},
				Addr:             ":8443",
				CertPath:         defaultCertPath,
				KeyPath:          defaultKeyPath,
				ServerSocketPath: "SOCKETPATH",
				TrustDomain:      "TRUSTDOMAIN",
				Cluster:          "CLUSTER",
			},
		},
		{
			name: "overrides",
			in: `
				log {
					level = "LEVELOVERRIDE"
					path = "PATHOVERRIDE"
				}
				addr = ":1234"
				cert_path = "CERTOVERRIDE"
				key_path = "KEYOVERRIDE"
				server_socket_path = "SOCKETPATHOVERRIDE"
				trust_domain = "TRUSTDOMAINOVERRIDE"
				cluster = "CLUSTEROVERRIDE"
			`,
			out: &Config{
				Log: LogConfig{
					Level: "LEVELOVERRIDE",
					Path:  "PATHOVERRIDE",
				},
				Addr:             ":1234",
				CertPath:         "CERTOVERRIDE",
				KeyPath:          "KEYOVERRIDE",
				ServerSocketPath: "SOCKETPATHOVERRIDE",
				TrustDomain:      "TRUSTDOMAINOVERRIDE",
				Cluster:          "CLUSTEROVERRIDE",
			},
		},
		{
			name: "bad HCL",
			in:   `INVALID`,
			err:  "unable to decode configuration",
		},
		{
			name: "missing server_socket_path",
			in: `
				trust_domain = "TRUSTDOMAIN"
				cluster = "CLUSTER"
			`,
			err: "server_socket_path must be specified",
		},
		{
			name: "missing trust domain",
			in: `
				cluster = "CLUSTER"
				server_socket_path = "SOCKETPATH"
			`,
			err: "trust_domain must be specified",
		},
		{
			name: "missing cluster",
			in: `
				trust_domain = "TRUSTDOMAIN"
				server_socket_path = "SOCKETPATH"
			`,
			err: "cluster must be specified",
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
