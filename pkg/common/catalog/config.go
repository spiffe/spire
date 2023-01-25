package catalog

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/printer"
	"github.com/hashicorp/hcl/hcl/token"
)

type PluginConfigs []PluginConfig

func (cs PluginConfigs) FilterByType(pluginType string) (matching PluginConfigs, remaining PluginConfigs) {
	for _, c := range cs {
		if c.Type == pluginType {
			matching = append(matching, c)
		} else {
			remaining = append(remaining, c)
		}
	}
	return matching, remaining
}

func (cs PluginConfigs) Find(pluginType, pluginName string) (PluginConfig, bool) {
	for _, c := range cs {
		if c.Type == pluginType && c.Name == pluginName {
			return c, true
		}
	}
	return PluginConfig{}, false
}

type PluginConfig struct {
	Type     string
	Name     string
	Path     string
	Args     []string
	Checksum string
	Data     string
	Disabled bool
}

func (c PluginConfig) IsEnabled() bool {
	return !c.Disabled
}

func (c *PluginConfig) IsExternal() bool {
	return c.Path != ""
}

type hclPluginConfig struct {
	PluginCmd      string   `hcl:"plugin_cmd"`
	PluginArgs     []string `hcl:"plugin_args"`
	PluginChecksum string   `hcl:"plugin_checksum"`
	PluginData     ast.Node `hcl:"plugin_data"`
	Enabled        *bool    `hcl:"enabled"`
}

func (c hclPluginConfig) IsEnabled() bool {
	if c.Enabled == nil {
		return true
	}
	return *c.Enabled
}

func (c hclPluginConfig) IsExternal() bool {
	return c.PluginCmd != ""
}

func PluginConfigsFromHCLNode(pluginsNode ast.Node) (PluginConfigs, error) {
	if pluginsNode == nil {
		return nil, errors.New("plugins node is nil")
	}
	pluginsList, ok := pluginsNode.(*ast.ObjectList)
	if !ok {
		return nil, fmt.Errorf("expected plugins node type %T but got %T", pluginsList, pluginsNode)
	}
	var pluginConfigs PluginConfigs
	for _, pluginObject := range pluginsList.Items {
		if len(pluginObject.Keys) != 2 {
			return nil, fmt.Errorf("plugin item expected to have two keys (type then name)")
		}

		pluginType, err := stringFromToken(pluginObject.Keys[0].Token)
		if err != nil {
			return nil, fmt.Errorf("invalid plugin type key %q: %w", pluginObject.Keys[0].Token.Text, err)
		}

		pluginName, err := stringFromToken(pluginObject.Keys[1].Token)
		if err != nil {
			return nil, fmt.Errorf("invalid plugin type name %q: %w", pluginObject.Keys[1].Token.Text, err)
		}

		var hclPluginConfig hclPluginConfig
		if err := hcl.DecodeObject(&hclPluginConfig, pluginObject.Val); err != nil {
			return nil, fmt.Errorf("failed to decode plugin config for %q/%q: %w", pluginType, pluginName, err)
		}

		pluginConfig, err := pluginConfigFromHCL(pluginType, pluginName, hclPluginConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create plugin config for %q/%q: %w", pluginType, pluginName, err)
		}

		pluginConfigs = append(pluginConfigs, pluginConfig)
	}
	return pluginConfigs, nil
}

func pluginConfigFromHCL(pluginType, pluginName string, hclPluginConfig hclPluginConfig) (PluginConfig, error) {
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

func stringFromToken(keyToken token.Token) (string, error) {
	switch keyToken.Type {
	case token.STRING, token.IDENT:
	default:
		return "", fmt.Errorf("expected STRING or IDENT but got %s", keyToken.Type)
	}
	value := keyToken.Value()
	stringValue, ok := value.(string)
	if !ok {
		// purely defensive
		return "", fmt.Errorf("expected %T but got %T", stringValue, value)
	}
	return stringValue, nil
}
