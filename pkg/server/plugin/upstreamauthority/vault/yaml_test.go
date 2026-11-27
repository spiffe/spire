package vault

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/yamlconfig"
	"github.com/stretchr/testify/require"
)

// TestConfigYAMLInline checks that YAML keys of the embedded configuration decode into it.
func TestConfigYAMLInline(t *testing.T) {
	config := new(Configuration)
	require.NoError(t, yamlconfig.Decode("vault_addr: https://vault\npki_mount_point: pki\n", config))
	require.Equal(t, "https://vault", config.VaultAddr)
}
