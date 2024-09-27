//go:build windows

package k8ssat

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/stretchr/testify/require"
)

func TestConfigureDefaultToken(t *testing.T) {
	for _, tt := range []struct {
		name            string
		trustDomain     string
		mountPoint      string
		config          string
		expectTokenPath string
	}{
		{
			name:            "mountPoint set",
			trustDomain:     "example.org",
			mountPoint:      "c:\\somepath",
			config:          `cluster = "production"`,
			expectTokenPath: "c:\\somepath\\var\\run\\secrets\\kubernetes.io\\serviceaccount\\token",
		},
		{
			name:            "no mountPoint",
			trustDomain:     "example.org",
			config:          `cluster = "production"`,
			expectTokenPath: "\\var\\run\\secrets\\kubernetes.io\\serviceaccount\\token",
		},
		{
			name:        "token path set on configuration",
			trustDomain: "example.org",
			mountPoint:  "c:\\somepath",
			config: `
			cluster = "production"
			token_path = "c:\\token"`,
			expectTokenPath: "c:\\token",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.mountPoint != "" {
				t.Setenv(containerMountPointEnvVar, tt.mountPoint)
			}

			p := New()
			var err error
			plugintest.Load(t, builtin(p), new(nodeattestor.V1),
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString(tt.trustDomain),
				}),
				plugintest.Configure(tt.config),
			)
			require.NoError(t, err)

			require.Equal(t, tt.expectTokenPath, p.config.tokenPath)
		})
	}
}
