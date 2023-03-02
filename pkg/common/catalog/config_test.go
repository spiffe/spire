package catalog

import (
	"testing"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/stretchr/testify/require"
)

func TestParsePluginConfigsFromHCLNode(t *testing.T) {
	test := func(t *testing.T, configIn string) {
		root := struct {
			Plugins ast.Node
		}{}
		err := hcl.Decode(&root, configIn)
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

	t.Run("HCL", func(t *testing.T) {
		config := `
			plugins {
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
			}
		`
		test(t, config)
	})

	t.Run("JSON", func(t *testing.T) {
		config := `{
			  "plugins": {
				"TYPE1": [
				  {
					"NAME3": {
						"plugin_data": "DATA3",
						"enabled": false
					}
				  }
				],
				"TYPE4": [
				  {
					"NAME4": [
					  {
					  }
					]
				  }
				],
				"TYPE1": [
				  {
					"NAME1": [
					  {
						"plugin_cmd": "CMD1",
						"plugin_data": "DATA1"
					  }
					]
				  }
				],
				"TYPE2": [
				  {
					"NAME2": [
					  {
						"plugin_cmd": "CMD2",
						"plugin_args": ["foo", "bar", "baz"],
						"plugin_checksum": "CHECKSUM2",
						"plugin_data": "DATA2",
						"enabled": true
					  }
					]
				  }
				]
			  }
			}`
		test(t, config)
	})

	t.Run("Plugin declared more than once", func(t *testing.T) {
		config := `{
			  "plugins": {
				"TYPE": [
					{
						"NAME": {}
					},
					{
						"NAME": {}
					}	
				]
			  }
			}`
		root := struct {
			Plugins ast.Node
		}{}
		err := hcl.Decode(&root, config)
		require.NoError(t, err)

		_, err = PluginConfigsFromHCLNode(root.Plugins)
		require.EqualError(t, err, `plugin "TYPE"/"NAME" declared more than once`)
	})

	t.Run("Unexpected key count", func(t *testing.T) {
		config := `
			plugins {
				"TYPE" "NAME" "BOGUS" {
				}
			}`
		root := struct {
			Plugins ast.Node
		}{}
		err := hcl.Decode(&root, config)
		require.NoError(t, err)

		_, err = PluginConfigsFromHCLNode(root.Plugins)
		require.EqualError(t, err, `expected one or two keys on the plugin item for type "TYPE" but got 3`)
	})
}
