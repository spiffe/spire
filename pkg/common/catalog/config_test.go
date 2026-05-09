package catalog

import (
	"os"
	"testing"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestParsePluginConfigsFromHCLNode(t *testing.T) {
	configs, err := PluginConfigsFromHCLNode(nil)
	require.NoError(t, err, "should fail when no plugins defined")
	require.Empty(t, configs)

	test := func(t *testing.T, configIn string) {
		root := struct {
			Plugins ast.Node `hcl:"plugins"`
		}{}
		err := hcl.Decode(&root, configIn)
		require.NoError(t, err)

		configs, err := PluginConfigsFromHCLNode(root.Plugins)
		require.NoError(t, err)

		pluginA := PluginConfig{
			Name:       "NAME3",
			Type:       "TYPE1",
			DataSource: FixedData{Data: `"DATA3"`, Format: ConfigFormatHCL},
			Disabled:   true,
		}
		pluginB := PluginConfig{
			Name: "NAME4",
			Type: "TYPE4",
		}
		pluginC := PluginConfig{
			Name:       "NAME1",
			Type:       "TYPE1",
			Path:       "CMD1",
			DataSource: FixedData{Data: `"DATA1"`, Format: ConfigFormatHCL},
			Disabled:   false,
		}
		pluginD := PluginConfig{
			Name:       "NAME5",
			Type:       "TYPE1",
			DataSource: FixedData{Data: `"foo" = "bar"`, Format: ConfigFormatHCL},
			Disabled:   false,
		}
		pluginE := PluginConfig{
			Name:       "NAME2",
			Type:       "TYPE2",
			Path:       "CMD2",
			Args:       []string{"foo", "bar", "baz"},
			Checksum:   "CHECKSUM2",
			DataSource: FixedData{Data: `"DATA2"`, Format: ConfigFormatHCL},
			Disabled:   false,
		}
		pluginF := PluginConfig{
			Name:       "NAME6",
			Type:       "TYPE3",
			DataSource: FixedData{Data: `"foo" = "bar"`, Format: ConfigFormatHCL},
			Disabled:   false,
		}
		pluginG := PluginConfig{
			Name:       "NAME7",
			Type:       "TYPE5",
			DataSource: FileData{Path: "FILE7", Format: ConfigFormatHCL},
		}
		pluginH := PluginConfig{
			Name:       "NAME8",
			Type:       "TYPE5",
			DataSource: nil,
		}

		// The declaration order should be preserved.
		require.Equal(t, PluginConfigs{
			pluginA,
			pluginB,
			pluginC,
			pluginD,
			pluginE,
			pluginF,
			pluginG,
			pluginH,
		}, configs)

		// A, C, and D are of type TYPE1
		matching, remaining := configs.FilterByType("TYPE1")

		require.Equal(t, PluginConfigs{
			pluginA,
			pluginC,
			pluginD,
		}, matching)

		require.Equal(t, PluginConfigs{
			pluginB,
			pluginE,
			pluginF,
			pluginG,
			pluginH,
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
				TYPE1 {
					NAME1 {
						plugin_cmd = "CMD1"
						plugin_data = "DATA1"
					}
					NAME5 plugin_data {
						"foo" = "bar"
					}
				}
				TYPE2 "NAME2" {
					plugin_cmd = "CMD2"
					plugin_args = ["foo", "bar", "baz"]
					plugin_checksum = "CHECKSUM2"
					plugin_data = "DATA2"
					enabled = true
				}
				TYPE3 "NAME6" "plugin_data" {
					"foo" = "bar"
				}
				TYPE5 "NAME7" {
					plugin_data_file = "FILE7"
				}
				TYPE5 "NAME8" {
					plugin_data = {}
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
				  },
				  {
					"NAME5": [
					  {
						"plugin_data": {
							"foo": "bar",
						}
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
				],
				"TYPE3": [
					{
						"NAME6": {
							"plugin_data": {
								"foo": "bar"
							}
						}
					}
				],
				"TYPE5": [
					{
						"NAME7": {
							"plugin_data_file": "FILE7"
						}
					},
					{
						"NAME8": {
							"plugin_data": {}
						}
					}
				],
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
				],
				"TYPE": [
					{
						"NAME": {}
					},
				]
			  }
			}`
		root := struct {
			Plugins ast.Node `hcl:"plugins"`
		}{}
		err := hcl.Decode(&root, config)
		require.NoError(t, err)

		_, err = PluginConfigsFromHCLNode(root.Plugins)
		require.EqualError(t, err, `plugin "TYPE"/"NAME" declared more than once`)
	})

	t.Run("Both plugin_data and plugin_data_file are declared", func(t *testing.T) {
		config := `
			plugins {
				TYPE "NAME" {
					plugin_data = "DATA"
					plugin_data_file = "DATAFILE"
				}
			}
		`
		root := struct {
			Plugins ast.Node `hcl:"plugins"`
		}{}
		err := hcl.Decode(&root, config)
		require.NoError(t, err)

		_, err = PluginConfigsFromHCLNode(root.Plugins)
		require.EqualError(t, err, `failed to create plugin config for "TYPE"/"NAME": only one of [plugin_data, plugin_data_file] can be used`)
	})
}

func TestConfigFormat_toProto(t *testing.T) {
	require.Equal(t, configv1.ConfigFormat_CONFIG_FORMAT_HCL, ConfigFormatHCL.ToProto())
	require.Equal(t, configv1.ConfigFormat_CONFIG_FORMAT_YAML, ConfigFormatYAML.ToProto())
}

func TestFixedData_Load(t *testing.T) {
	d := FixedData{Data: "hello", Format: ConfigFormatYAML}
	data, format, err := d.Load()
	require.NoError(t, err)
	require.Equal(t, "hello", data)
	require.Equal(t, ConfigFormatYAML, format)
}

func yamlNode(t *testing.T, text string) *RawYAML {
	var doc yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(text), &doc))
	return &RawYAML{Node: doc.Content[0]}
}

func TestPluginConfigsFromYAML(t *testing.T) {
	node := yamlNode(t, `
NodeAttestor:
  k8s_psat:
    pluginCmd: ./attestor
    pluginChecksum: abc123
    pluginArgs: ["--arg1", "--arg2"]
    pluginData:
      cluster: prod
    enabled: true
  disabled_plugin:
    pluginCmd: ./attestor2
    enabled: false
KeyManager:
  disk:
    pluginDataFile: keymanager.yaml
  memory:
    pluginData: {}
`)

	configs, err := PluginConfigsFromYAML(node)
	require.NoError(t, err)
	require.Equal(t, PluginConfigs{
		{
			Type:       "NodeAttestor",
			Name:       "k8s_psat",
			Path:       "./attestor",
			Checksum:   "abc123",
			Args:       []string{"--arg1", "--arg2"},
			DataSource: FixedData{Data: "cluster: prod\n", Format: ConfigFormatYAML},
		},
		{
			Type:     "NodeAttestor",
			Name:     "disabled_plugin",
			Path:     "./attestor2",
			Disabled: true,
		},
		{
			Type:       "KeyManager",
			Name:       "disk",
			DataSource: FileData{Path: "keymanager.yaml", Format: ConfigFormatYAML},
		},
		{
			Type: "KeyManager",
			Name: "memory",
		},
	}, configs)
}

func TestPluginConfigsFromYAML_Nil(t *testing.T) {
	configs, err := PluginConfigsFromYAML(nil)
	require.NoError(t, err)
	require.Nil(t, configs)
}

func TestPluginConfigsFromYAML_Errors(t *testing.T) {
	for _, tt := range []struct {
		name, config, err string
	}{
		{"both data sources", "T:\n  n:\n    pluginData: {k: v}\n    pluginDataFile: f.yaml\n", "only one of"},
		{"unknown key", "T:\n  n:\n    plugin_cmd: ./p\n", "field plugin_cmd not found"},
		{"plugins not a mapping", "[a]", "plugins must be a mapping"},
		{"type not a mapping", "T: [a]", `plugins of type "T" must be a mapping`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PluginConfigsFromYAML(yamlNode(t, tt.config))
			require.ErrorContains(t, err, tt.err)
		})
	}
}

func TestFileData_Load(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "test*.yaml")
	require.NoError(t, err)
	_, err = f.WriteString("key: value")
	require.NoError(t, err)
	f.Close()

	d := FileData{Path: f.Name(), Format: ConfigFormatYAML}
	data, format, err := d.Load()
	require.NoError(t, err)
	require.Equal(t, "key: value", data)
	require.Equal(t, ConfigFormatYAML, format)
}
