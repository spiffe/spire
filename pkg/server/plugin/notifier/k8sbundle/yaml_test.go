package k8sbundle

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/plugindecode"
	"github.com/stretchr/testify/require"
)

// TestConfigYAMLInline checks that YAML keys of the embedded configuration decode into it.
func TestConfigYAMLInline(t *testing.T) {
	config := new(Configuration)
	require.NoError(t, plugindecode.DecodeYAML("namespace: spire\nclusters:\n- namespace: other\n", config))
	require.Equal(t, "spire", config.Namespace)
}
