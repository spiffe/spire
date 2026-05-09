package vault

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/plugindecode"
	"github.com/stretchr/testify/require"
)

// TestConfigYAMLInline checks that YAML keys of the embedded configuration decode into it.
func TestConfigYAMLInline(t *testing.T) {
	config := new(Configuration)
	require.NoError(t, plugindecode.DecodeYAML("vaultAddr: https://vault\npkiMountPoint: pki\n", config))
	require.Equal(t, "https://vault", config.VaultAddr)
}
