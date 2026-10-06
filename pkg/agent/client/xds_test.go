package client

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestXDSTarget(t *testing.T) {
	for _, tt := range []struct {
		name         string
		listenerName string
		target       string
		err          string
	}{
		{
			name:         "plain name",
			listenerName: "spire-server",
			target:       "xds:///spire-server",
		},
		{
			name:         "host:port name",
			listenerName: "spire-server.example.org:8081",
			target:       "xds:///spire-server.example.org:8081",
		},
		{
			name:         "query dropped",
			listenerName: "spire-server?x=1",
			err:          `invalid xDS listener name "spire-server?x=1": gRPC would resolve it as "spire-server"`,
		},
		{
			name:         "fragment dropped",
			listenerName: "spire-server#x",
			err:          `invalid xDS listener name "spire-server#x": gRPC would resolve it as "spire-server"`,
		},
		{
			name:         "percent escape decoded",
			listenerName: "spire%2Dserver",
			err:          `invalid xDS listener name "spire%2Dserver": gRPC would resolve it as "spire-server"`,
		},
		{
			name:         "unparsable",
			listenerName: "spire%zz",
			err:          `invalid xDS listener name "spire%zz": parse "xds:///spire%zz": invalid URL escape "%zz"`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			target, err := XDSTarget(tt.listenerName)
			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.target, target)
		})
	}
}

func TestValidateXDSBootstrap(t *testing.T) {
	for _, tt := range []struct {
		name   string
		config string
		err    string
	}{
		{
			name:   "unix socket insecure",
			config: `{"xds_servers":[{"server_uri":"unix:///run/xds.sock","channel_creds":[{"type":"insecure"}]}]}`,
		},
		{
			name:   "unix abstract insecure",
			config: `{"xds_servers":[{"server_uri":"unix-abstract:xds","channel_creds":[{"type":"insecure"}]}]}`,
		},
		{
			name:   "localhost insecure",
			config: `{"xds_servers":[{"server_uri":"localhost:18000","channel_creds":[{"type":"insecure"}]}]}`,
		},
		{
			name:   "ipv4 loopback insecure",
			config: `{"xds_servers":[{"server_uri":"127.0.0.1:18000","channel_creds":[{"type":"insecure"}]}]}`,
		},
		{
			name:   "ipv6 loopback insecure",
			config: `{"xds_servers":[{"server_uri":"[::1]:18000","channel_creds":[{"type":"insecure"}]}]}`,
		},
		{
			name:   "dns scheme localhost insecure",
			config: `{"xds_servers":[{"server_uri":"dns:///localhost:18000","channel_creds":[{"type":"insecure"}]}]}`,
		},
		{
			name:   "remote tls",
			config: `{"xds_servers":[{"server_uri":"xds.example.org:18000","channel_creds":[{"type":"tls"}]}]}`,
		},
		{
			name:   "remote unsupported creds skipped before tls",
			config: `{"xds_servers":[{"server_uri":"xds.example.org:18000","channel_creds":[{"type":"unknown"},{"type":"tls"}]}]}`,
		},
		{
			name:   "remote insecure",
			config: `{"xds_servers":[{"server_uri":"xds.example.org:18000","channel_creds":[{"type":"insecure"}]}]}`,
			err:    `xDS server "xds.example.org:18000" is not local and uses "insecure" channel credentials; must use "tls"`,
		},
		{
			name:   "remote insecure selected before tls",
			config: `{"xds_servers":[{"server_uri":"xds.example.org:18000","channel_creds":[{"type":"insecure"},{"type":"tls"}]}]}`,
			err:    `xDS server "xds.example.org:18000" is not local and uses "insecure" channel credentials; must use "tls"`,
		},
		{
			name:   "remote google_default",
			config: `{"xds_servers":[{"server_uri":"xds.example.org:18000","channel_creds":[{"type":"google_default"}]}]}`,
			err:    `xDS server "xds.example.org:18000" is not local and uses "google_default" channel credentials; must use "tls"`,
		},
		{
			name:   "dns authority is not local",
			config: `{"xds_servers":[{"server_uri":"dns://8.8.8.8/localhost:18000","channel_creds":[{"type":"insecure"}]}]}`,
			err:    `xDS server "dns://8.8.8.8/localhost:18000" is not local and uses "insecure" channel credentials; must use "tls"`,
		},
		{
			name:   "remote fallback insecure",
			config: `{"xds_servers":[{"server_uri":"localhost:18000","channel_creds":[{"type":"insecure"}]},{"server_uri":"xds.example.org:18000","channel_creds":[{"type":"insecure"}]}]}`,
			err:    `xDS server "xds.example.org:18000" is not local and uses "insecure" channel credentials; must use "tls"`,
		},
		{
			name:   "authority remote insecure",
			config: `{"xds_servers":[{"server_uri":"localhost:18000","channel_creds":[{"type":"insecure"}]}],"authorities":{"other":{"xds_servers":[{"server_uri":"xds.example.org:18000","channel_creds":[{"type":"insecure"}]}]}}}`,
			err:    `xDS server "xds.example.org:18000" is not local and uses "insecure" channel credentials; must use "tls"`,
		},
		{
			name:   "no servers",
			config: `{}`,
			err:    "xDS bootstrap has no xds_servers",
		},
		{
			name:   "malformed",
			config: `{`,
			err:    "failed to parse xDS bootstrap: unexpected end of JSON input",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(xdsBootstrapFileEnv, "")
			t.Setenv(xdsBootstrapConfigEnv, tt.config)
			err := ValidateXDSBootstrap()
			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateXDSBootstrapFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"xds_servers":[{"server_uri":"xds.example.org:18000","channel_creds":[{"type":"insecure"}]}]}`), 0600))

	// File takes precedence over inline config.
	t.Setenv(xdsBootstrapFileEnv, path)
	t.Setenv(xdsBootstrapConfigEnv, `{"xds_servers":[{"server_uri":"localhost:18000","channel_creds":[{"type":"insecure"}]}]}`)
	require.ErrorContains(t, ValidateXDSBootstrap(), "is not local")

	t.Setenv(xdsBootstrapFileEnv, filepath.Join(t.TempDir(), "missing.json"))
	require.ErrorContains(t, ValidateXDSBootstrap(), "failed to read xDS bootstrap")
}

func TestValidateXDSBootstrapUnset(t *testing.T) {
	t.Setenv(xdsBootstrapFileEnv, "")
	t.Setenv(xdsBootstrapConfigEnv, "")
	require.EqualError(t, ValidateXDSBootstrap(), "xDS bootstrap not configured; set GRPC_XDS_BOOTSTRAP or GRPC_XDS_BOOTSTRAP_CONFIG")
}
