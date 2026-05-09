//go:build !windows

package docker

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/plugindecode"
	"github.com/stretchr/testify/require"
)

// TestConfigYAMLInline checks that YAML keys of the embedded configuration decode into it.
func TestConfigYAMLInline(t *testing.T) {
	config := new(dockerPluginConfig)
	require.NoError(t, plugindecode.DecodeYAML("dockerSocketPath: unix:///docker.sock\n", config))
	require.Equal(t, "unix:///docker.sock", config.DockerSocketPath)
}
