package catalog

import (
	"bytes"
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
		return nil, nil
	}

	pluginsList, ok := pluginsNode.(*ast.ObjectList)
	if !ok {
		return nil, fmt.Errorf("expected plugins node type %T but got %T", pluginsList, pluginsNode)
	}

	order, err := determinePluginOrder(pluginsList)
	if err != nil {
		return nil, err
	}

	var pluginsMaps pluginsMapList
	if err := hcl.DecodeObject(&pluginsMaps, pluginsNode); err != nil {
		return nil, fmt.Errorf("failed to decode plugins config: %w", err)
	}

	// Santity check the length of the pluginsMapList and those found when
	// determining order. If this mismatches, it's a bug.
	if pluginsLen := pluginsMaps.Len(); pluginsLen != len(order) {
		return nil, fmt.Errorf("bug: expected %d plugins but got %d", len(order), pluginsLen)
	}

	var pluginConfigs PluginConfigs
	for _, ident := range order {
		hclPluginConfig, ok := pluginsMaps.FindPluginConfig(ident.Type, ident.Name)
		if !ok {
			// This would be a programmer error. We should always be able to
			// locate the plugin configuration in one of the maps.
			return nil, fmt.Errorf("bug: plugin config for %q/%q not located", ident.Type, ident.Name)
		}
		pluginConfig, err := pluginConfigFromHCL(ident.Type, ident.Name, hclPluginConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create plugin config for %q/%q: %w", ident.Type, ident.Name, err)
		}
		pluginConfigs = append(pluginConfigs, pluginConfig)
	}
	return pluginConfigs, nil
}

type pluginIdent struct {
	Type string
	Name string
}

func determinePluginOrder(pluginsList *ast.ObjectList) ([]pluginIdent, error) {
	var order []pluginIdent
	appendOrder := func(pluginType, pluginName string) {
		order = append(order, pluginIdent{Type: pluginType, Name: pluginName})
	}

	stackKeys := func(stack []ast.Node) (keys []string) {
		for _, s := range stack {
			if objectItem, ok := s.(*ast.ObjectItem); ok {
				for _, k := range objectItem.Keys {
					key, err := stringFromToken(k.Token)
					if err != nil {
						return nil
					}
					keys = append(keys, key)
				}
			}
		}
		return keys
	}

	// Walk the AST, pushing and popping nodes from an "object" stack. At
	// each step, determine if we've accumulated object keys at least 2 deep.
	// If so, we've found a plugin definition and add the plugin identifier
	// to the ordering.
	//
	// This accommodates nesting of all shapes and sizes, for example:
	//
	// "NodeAttestor" {
	//     "k8s_psat" {
	//         plugin_data {
	//         }
	//     }
	// }
	//
	// "NodeAttestor" "k8s_psat" {
	//     plugin_data {
	//     }
	// }
	//
	// "NodeAttestor" "k8s_psat" plugin_data {
	// }
	//
	//
	var stack []ast.Node
	ast.Walk(pluginsList, ast.WalkFunc(func(n ast.Node) (ast.Node, bool) {
		if n == nil {
			stack = stack[:len(stack)-1]
			return n, false
		}
		stack = append(stack, n)
		keys := stackKeys(stack)
		if len(keys) >= 2 {
			appendOrder(keys[0], keys[1])
			// Since we've found an object item for the plugin, pop it from
			// the stack and do not recurse.
			stack = stack[:len(stack)-1]
			return n, false
		}
		return n, true
	}))

	// Check for duplicates
	seen := make(map[pluginIdent]struct{})
	for _, ident := range order {
		if _, ok := seen[ident]; ok {
			return nil, fmt.Errorf("plugin %q/%q declared more than once", ident.Type, ident.Name)
		}
		seen[ident] = struct{}{}
	}
	return order, nil
}

type pluginsMapList []map[string]map[string]hclPluginConfig

func (m pluginsMapList) FindPluginConfig(pluginType, pluginName string) (hclPluginConfig, bool) {
	for _, pluginsMap := range m {
		pluginsForType, ok := pluginsMap[pluginType]
		if !ok {
			continue
		}
		pluginConfig, ok := pluginsForType[pluginName]
		if !ok {
			continue
		}
		return pluginConfig, true
	}
	return hclPluginConfig{}, false
}

func (m pluginsMapList) Len() int {
	n := 0
	for _, pluginsMap := range m {
		for _, pluginsForType := range pluginsMap {
			n += len(pluginsForType)
		}
	}
	return n
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
	if !keyToken.Type.IsIdentifier() {
		return "", fmt.Errorf("expected identifier token but got %s at %s", keyToken.Type, keyToken.Pos)
	}
	return fmt.Sprint(keyToken.Value()), nil
}
