//go:build !windows
// +build !windows

package k8spsat

import (
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/stretchr/testify/require"
)

func TestConfigureDefaultToken(t *testing.T) {
	p := New()
	var err error
	plugintest.Load(t, builtin(p), new(nodeattestor.V1), plugintest.CaptureConfigureError(&err), plugintest.Configure(`cluster = "production"`))
	require.NoError(t, err)
	require.Equal(t, "/var/run/secrets/tokens/spire-agent", p.config.tokenPath)

	plugintest.Load(t, builtin(p), new(nodeattestor.V1), plugintest.CaptureConfigureError(&err), plugintest.Configure(`
			cluster = "production"
			token_path = "/tmp/token"`))
	require.NoError(t, err)

	require.Equal(t, "/tmp/token", p.config.tokenPath)
}
