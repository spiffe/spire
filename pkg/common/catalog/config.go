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
	Args     []string
	Checksum string
	Data     string
	Disabled bool
}

func (c *PluginConfig) IsExternal() bool {
	return c.Path != ""
}

// HCLPluginConfig serves as an intermediary struct. We pass this to the
// HCL library for parsing, except the parser won't parse pluginData
// as a string.
type HCLPluginConfig struct {
	PluginCmd      string   `hcl:"plugin_cmd"`
	PluginArgs     []string `hcl:"plugin_args"`
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

func (c HCLPluginConfig) IsExternal() bool {
	return c.PluginCmd != ""
}

type HCLPluginConfigMap map[string]map[string]HCLPluginConfig

func ParsePluginConfigsFromHCL(config string) ([]PluginConfig, error) {
	var hclConfig HCLPluginConfigMap
	if err := hcl.Decode(&hclConfig, config); err != nil {
		return nil, errs.New("unable to decode plugin config: %v", err)
	}
	return PluginConfigsFromHCL(hclConfig)
}

func PluginConfigsFromHCL(hclPlugins HCLPluginConfigMap) ([]PluginConfig, error) {
	var pluginConfigs []PluginConfig
	for pluginType, pluginsForType := range hclPlugins {
		for pluginName, hclPluginConfig := range pluginsForType {
			pluginConfig, err := PluginConfigFromHCL(pluginType, pluginName, hclPluginConfig)
			if err != nil {
				return nil, err
			}
			pluginConfigs = append(pluginConfigs, pluginConfig)
		}
	}
	return pluginConfigs, nil
}

func PluginConfigFromHCL(pluginType, pluginName string, hclPluginConfig HCLPluginConfig) (PluginConfig, error) {
	var data bytes.Buffer
	if hclPluginConfig.PluginData != nil {
		if err := printer.DefaultConfig.Fprint(&data, hclPluginConfig.PluginData); err != nil {
			return PluginConfig{}, err
		}
	}

	return PluginConfig{
		Name:     pluginName,
		Type:     pluginType,
		Path:     hclPluginConfig.PluginCmd,
		Args:     hclPluginConfig.PluginArgs,
		Checksum: hclPluginConfig.PluginChecksum,
		Data:     data.String(),
		Disabled: !hclPluginConfig.IsEnabled(),
	}, nil
}
