package plugindecode_test

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugindecode"
	"github.com/stretchr/testify/require"
)

type testConfig struct {
	KeysPath string `hcl:"keys_path"  yaml:"keysPath"`
	MaxKeys  int    `hcl:"max_keys"   yaml:"maxKeys"`
}

func TestDecodeConfig_HCL(t *testing.T) {
	hclText := `keys_path = "/tmp/keys"
max_keys = 10`
	var cfg testConfig
	err := plugindecode.DecodeConfig(hclText, catalog.ConfigFormatHCL, &cfg)
	require.NoError(t, err)
	require.Equal(t, "/tmp/keys", cfg.KeysPath)
	require.Equal(t, 10, cfg.MaxKeys)
}

func TestDecodeConfig_YAML(t *testing.T) {
	yamlText := `keysPath: /tmp/keys
maxKeys: 10`
	var cfg testConfig
	err := plugindecode.DecodeConfig(yamlText, catalog.ConfigFormatYAML, &cfg)
	require.NoError(t, err)
	require.Equal(t, "/tmp/keys", cfg.KeysPath)
	require.Equal(t, 10, cfg.MaxKeys)
}

func TestDecodeConfig_EmptyHCL(t *testing.T) {
	var cfg testConfig
	err := plugindecode.DecodeConfig("", catalog.ConfigFormatHCL, &cfg)
	require.NoError(t, err)
}

func TestDecodeConfig_EmptyYAML(t *testing.T) {
	var cfg testConfig
	err := plugindecode.DecodeConfig("", catalog.ConfigFormatYAML, &cfg)
	require.NoError(t, err)
}

func TestDecodeConfig_InvalidHCL(t *testing.T) {
	var cfg testConfig
	err := plugindecode.DecodeConfig("not { valid hcl !!!", catalog.ConfigFormatHCL, &cfg)
	require.Error(t, err)
}

func TestDecodeConfig_InvalidYAML(t *testing.T) {
	var cfg testConfig
	err := plugindecode.DecodeConfig(":\n  - bad: [yaml", catalog.ConfigFormatYAML, &cfg)
	require.Error(t, err)
}

func TestDecodeConfig_YAMLUnknownKey(t *testing.T) {
	var cfg testConfig
	err := plugindecode.DecodeConfig("keys_path: /tmp/keys\n", catalog.ConfigFormatYAML, &cfg)
	require.ErrorContains(t, err, "field keys_path not found")
}
