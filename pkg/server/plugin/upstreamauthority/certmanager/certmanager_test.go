package certmanager

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestLoadConfig(t *testing.T) {
	tests := map[string]struct {
		inpConfig string
		expErr    bool
		expConfig *Config
	}{
		"if config is malformed, expect error": {
			inpConfig: `
         issuer_name_foo = "my-issuer"
			`,
			expErr:    true,
			expConfig: nil,
		},
		"if config is fully populated, return config": {
			inpConfig: `
         issuer_name = "my-issuer"
				 issuer_kind = "my-kind"
				 issuer_group = "my-group"
				 namespace = "my-namespace"
				 kube_config_path = "/path/to/config"
			`,
			expErr: false,
			expConfig: &Config{
				IssuerName:         "my-issuer",
				IssuerKind:         "my-kind",
				IssuerGroup:        "my-group",
				Namespace:          "my-namespace",
				KubeConfigFilePath: "/path/to/config",
			},
		},
		"if config is partly populated, expect defaulting": {
			inpConfig: `
         issuer_name = "my-issuer"
				 namespace = "my-namespace"
				 kube_config_path = "/path/to/config"
			`,
			expErr: false,
			expConfig: &Config{
				IssuerName:         "my-issuer",
				IssuerKind:         "Issuer",
				IssuerGroup:        "cert-manager.io",
				Namespace:          "my-namespace",
				KubeConfigFilePath: "/path/to/config",
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			plugin := New()
			plugin.SetLogger(hclog.Default())

			config, err := plugin.loadConfig(&spi.ConfigureRequest{
				Configuration: test.inpConfig,
			})

			require.Equal(t, test.expErr, (err != nil))
			if err != nil {
				require.Equal(t, codes.InvalidArgument, status.Code(err))
			}
			require.Equal(t, test.expConfig, config)
		})
	}
}
