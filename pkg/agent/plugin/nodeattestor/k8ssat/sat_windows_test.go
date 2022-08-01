//go:build windows
// +build windows

package k8ssat

import (
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/stretchr/testify/require"
)

func TestConfigureDefaultToken(t *testing.T) {
	for _, tt := range []struct {
		name            string
		mountPoint      string
		config          string
		expectTokenPath string
	}{
		{
			name:            "mountPoint set",
			mountPoint:      "c:\\somepath",
			config:          `cluster = "production"`,
			expectTokenPath: "c:\\somepath\\var\\run\\secrets\\kubernetes.io\\serviceaccount\\token",
		},
		{
			name:            "no mountPoint",
			config:          `cluster = "production"`,
			expectTokenPath: "\\var\\run\\secrets\\kubernetes.io\\serviceaccount\\token",
		},
		{
			name:       "token path set on configuration",
			mountPoint: "c:\\somepath",
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
			plugintest.Load(t, builtin(p), new(nodeattestor.V1), plugintest.CaptureConfigureError(&err), plugintest.Configure(tt.config))
			require.NoError(t, err)

			require.Equal(t, tt.expectTokenPath, p.config.tokenPath)
		})
	}
}
