package catalog

import (
	"bytes"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/printer"
	"github.com/zeebo/errs"
)

type PluginConfig struct {
	Name     string
	Type     string
	Path     string
	Checksum string
	Data     string
	Disabled bool
}

// HCLPluginConfig serves as an intermediary struct. We pass this to the
// HCL library for parsing, except the parser won't parse pluginData
// as a string.
type HCLPluginConfig struct {
	PluginCmd      string   `hcl:"plugin_cmd"`
	PluginChecksum string   `hcl:"plugin_checksum"`
	PluginData     ast.Node `hcl:"plugin_data"`
	Enabled        *bool    `hcl:"enabled"`
}

func (c HCLPluginConfig) IsEnabled() bool {
	if c.Enabled == nil {
		return true
	}

	return *c.Enabled
}

type HCLPluginConfigMap map[string]map[string]HCLPluginConfig

func ParsePluginConfigFromHCL(config string) ([]PluginConfig, error) {
	var hclConfig HCLPluginConfigMap
	if err := hcl.Decode(&hclConfig, config); err != nil {
		return nil, errs.New("unable to decode plugin config: %v", err)
	}
	return PluginConfigFromHCL(hclConfig)
}

func PluginConfigFromHCL(hclPlugins HCLPluginConfigMap) ([]PluginConfig, error) {
	var pluginConfigs []PluginConfig
	for pluginType, pluginsForType := range hclPlugins {
		for pluginName, hclPluginConfig := range pluginsForType {
			var data bytes.Buffer
			if err := printer.DefaultConfig.Fprint(&data, hclPluginConfig.PluginData); err != nil {
				return nil, err
			}

			pluginConfigs = append(pluginConfigs, PluginConfig{
				Name:     pluginName,
				Type:     pluginType,
				Path:     hclPluginConfig.PluginCmd,
				Checksum: hclPluginConfig.PluginChecksum,
				Data:     data.String(),
				Disabled: !hclPluginConfig.IsEnabled(),
			})
		}
	}

	return pluginConfigs, nil
}
