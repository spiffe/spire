// Package configtest contains helpers for testing configuration parsing.
package configtest

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/token"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugindecode"
	"github.com/spiffe/spire/pkg/common/yamlconfig"
	"github.com/stretchr/testify/require"
)

// DecodePluginData decodes the data of the named plugin so that it can be
// compared across formats. It returns nil to fall back to a generic map.
type DecodePluginData func(t *testing.T, pluginType, pluginName, data string, format catalog.ConfigFormat) any

// RequireYAMLParity requires that a YAML configuration decodes to the same
// values as its HCL twin. HCL-only ast.Node fields are ignored, so callers
// should first convert them into their YAML counterparts.
func RequireYAMLParity(t *testing.T, hclConf, yamlConf any, hclPlugins ast.Node, yamlPlugins *yamlconfig.Raw, decode DecodePluginData) {
	require.Empty(t, cmp.Diff(hclConf, yamlConf,
		cmpopts.IgnoreInterfaces(struct{ ast.Node }{}),
		cmpopts.IgnoreTypes(map[string][]token.Pos{}, &yamlconfig.Raw{}),
	))

	hclPluginConfigs, err := catalog.PluginConfigsFromHCLNode(hclPlugins)
	require.NoError(t, err)
	yamlPluginConfigs, err := catalog.PluginConfigsFromYAML(yamlPlugins)
	require.NoError(t, err)
	require.Len(t, yamlPluginConfigs, len(hclPluginConfigs))

	for i, hclPlugin := range hclPluginConfigs {
		yamlPlugin := yamlPluginConfigs[i]
		hclData, hclIsFixed := hclPlugin.DataSource.(catalog.FixedData)
		yamlData, yamlIsFixed := yamlPlugin.DataSource.(catalog.FixedData)
		if !hclIsFixed || !yamlIsFixed {
			require.Equal(t, hclPlugin, yamlPlugin)
			continue
		}

		hclPlugin.DataSource, yamlPlugin.DataSource = nil, nil
		require.Equal(t, hclPlugin, yamlPlugin)
		require.Equal(t,
			decodeData(t, hclPlugin, hclData, decode),
			decodeData(t, yamlPlugin, yamlData, decode),
			"data of plugin %s %q", hclPlugin.Type, hclPlugin.Name)
	}
}

func decodeData(t *testing.T, plugin catalog.PluginConfig, data catalog.FixedData, decode DecodePluginData) any {
	if decode != nil {
		if out := decode(t, plugin.Type, plugin.Name, data.Data, data.Format); out != nil {
			return out
		}
	}
	var out map[string]any
	require.NoError(t, plugindecode.DecodeConfig(data.Data, data.Format, &out))
	return out
}
