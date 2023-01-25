package catalog

import (
	"testing"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/stretchr/testify/require"
)

func TestParsePluginConfigsFromHCLNode(t *testing.T) {
	root := struct {
		Plugins ast.Node
	}{}
	err := hcl.Decode(&root, `plugins {
	TYPE1 "NAME3" {
		plugin_data = "DATA3"
		enabled = false
	}
	TYPE4 "NAME4" {
	}
	TYPE1 "NAME1" {
		plugin_cmd = "CMD1"
		plugin_data = "DATA1"
	}
	TYPE2 "NAME2" {
		plugin_cmd = "CMD2"
		plugin_args = ["foo", "bar", "baz"]
		plugin_checksum = "CHECKSUM2"
		plugin_data = "DATA2"
		enabled = true
	}
}`)
	require.NoError(t, err)

	configs, err := PluginConfigsFromHCLNode(root.Plugins)
	require.NoError(t, err)

	pluginA := PluginConfig{
		Name:     "NAME3",
		Type:     "TYPE1",
		Data:     `"DATA3"`,
		Disabled: true,
	}
	pluginB := PluginConfig{
		Name: "NAME4",
		Type: "TYPE4",
	}
	pluginC := PluginConfig{
		Name:     "NAME1",
		Type:     "TYPE1",
		Path:     "CMD1",
		Data:     `"DATA1"`,
		Disabled: false,
	}
	pluginD := PluginConfig{
		Name:     "NAME2",
		Type:     "TYPE2",
		Path:     "CMD2",
		Args:     []string{"foo", "bar", "baz"},
		Checksum: "CHECKSUM2",
		Data:     `"DATA2"`,
		Disabled: false,
	}

	// The declaration order should be preserved.
	require.Equal(t, PluginConfigs{
		pluginA,
		pluginB,
		pluginC,
		pluginD,
	}, configs)

	// Only A and C are of type TYPE1
	matching, remaining := configs.FilterByType("TYPE1")

	require.Equal(t, PluginConfigs{
		pluginA,
		pluginC,
	}, matching)

	require.Equal(t, PluginConfigs{
		pluginB,
		pluginD,
	}, remaining)

	c, ok := configs.Find("TYPE1", "NAME1")
	require.Equal(t, pluginC, c)
	require.True(t, ok)

	_, ok = configs.Find("WHATEVER", "NAME1")
	require.False(t, ok)

	_, ok = configs.Find("TYPE1", "WHATEVER")
	require.False(t, ok)
}
