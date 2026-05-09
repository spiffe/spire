package catalog

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/printer"
	"github.com/hashicorp/hcl/hcl/token"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"go.yaml.in/yaml/v3"
)

// ConfigFormat identifies the serialization format of a plugin configuration string.
type ConfigFormat int

const (
	ConfigFormatHCL ConfigFormat = iota
	ConfigFormatYAML
)

func (f ConfigFormat) ToProto() configv1.ConfigFormat {
	switch f {
	case ConfigFormatYAML:
		return configv1.ConfigFormat_CONFIG_FORMAT_YAML
	default:
		return configv1.ConfigFormat_CONFIG_FORMAT_HCL
	}
}

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
	Type       string
	Name       string
	Path       string
	Args       []string
	Checksum   string
	DataSource DataSource
	Disabled   bool
}

func (c PluginConfig) IsEnabled() bool {
	return !c.Disabled
}

func (c *PluginConfig) IsExternal() bool {
	return c.Path != ""
}

type DataSource interface {
	Load() (string, ConfigFormat, error)
	IsDynamic() bool
}

type FixedData struct {
	Data   string
	Format ConfigFormat
}

func (d FixedData) Load() (string, ConfigFormat, error) {
	return d.Data, d.Format, nil
}

func (d FixedData) IsDynamic() bool { return false }

type FileData struct {
	Path   string
	Format ConfigFormat
}

func (d FileData) Load() (string, ConfigFormat, error) {
	data, err := os.ReadFile(d.Path)
	if err != nil {
		return "", d.Format, err
	}
	return string(data), d.Format, nil
}

func (d FileData) IsDynamic() bool { return true }

type hclPluginConfig struct {
	PluginCmd      string   `hcl:"plugin_cmd" yaml:"pluginCmd"`
	PluginArgs     []string `hcl:"plugin_args" yaml:"pluginArgs"`
	PluginChecksum string   `hcl:"plugin_checksum" yaml:"pluginChecksum"`
	PluginData     ast.Node `hcl:"plugin_data" yaml:"-"`
	PluginDataFile *string  `hcl:"plugin_data_file" yaml:"pluginDataFile"`
	Enabled        *bool    `hcl:"enabled" yaml:"enabled"`
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

	// Sanity check the length of the pluginsMapList and those found when
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
	if hclPluginConfig.PluginData != nil && hclPluginConfig.PluginDataFile != nil {
		return PluginConfig{}, errors.New("only one of [plugin_data, plugin_data_file] can be used")
	}

	var dataSource DataSource

	if hclPluginConfig.PluginData != nil {
		var buf bytes.Buffer
		if err := printer.DefaultConfig.Fprint(&buf, hclPluginConfig.PluginData); err != nil {
			return PluginConfig{}, err
		}
		if data := buf.String(); data != "" {
			dataSource = FixedData{Data: data, Format: ConfigFormatHCL}
		}
	}

	if hclPluginConfig.PluginDataFile != nil {
		dataSource = FileData{Path: *hclPluginConfig.PluginDataFile, Format: ConfigFormatHCL}
	}

	return PluginConfig{
		Name:       pluginName,
		Type:       pluginType,
		Path:       hclPluginConfig.PluginCmd,
		Args:       hclPluginConfig.PluginArgs,
		Checksum:   hclPluginConfig.PluginChecksum,
		DataSource: dataSource,
		Disabled:   !hclPluginConfig.IsEnabled(),
	}, nil
}

// RawYAML captures a YAML value without decoding it. Unlike a yaml.Node
// field, it is not subject to the decoder's unknown-field checks.
type RawYAML struct {
	Node *yaml.Node
}

func (r *RawYAML) UnmarshalYAML(node *yaml.Node) error {
	r.Node = node
	return nil
}

type yamlPluginConfig struct {
	PluginCmd      string   `yaml:"pluginCmd"`
	PluginArgs     []string `yaml:"pluginArgs"`
	PluginChecksum string   `yaml:"pluginChecksum"`
	PluginData     *RawYAML `yaml:"pluginData"`
	PluginDataFile *string  `yaml:"pluginDataFile"`
	Enabled        *bool    `yaml:"enabled"`
}

// PluginConfigsFromYAML parses the plugins section of a YAML config, laid out
// as plugins.<pluginType>.<pluginName>. Plugins keep their order in the file.
func PluginConfigsFromYAML(raw *RawYAML) (PluginConfigs, error) {
	if raw == nil || raw.Node == nil {
		return nil, nil
	}
	node := raw.Node
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("plugins must be a mapping at line %d", node.Line)
	}

	var pluginConfigs PluginConfigs
	for i := 0; i < len(node.Content); i += 2 {
		pluginType, pluginsForType := node.Content[i].Value, node.Content[i+1]
		if pluginsForType.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("plugins of type %q must be a mapping at line %d", pluginType, pluginsForType.Line)
		}
		for j := 0; j < len(pluginsForType.Content); j += 2 {
			pluginName := pluginsForType.Content[j].Value
			pc, err := pluginConfigFromYAML(pluginType, pluginName, pluginsForType.Content[j+1])
			if err != nil {
				return nil, fmt.Errorf("failed to create plugin config for %q/%q: %w", pluginType, pluginName, err)
			}
			pluginConfigs = append(pluginConfigs, pc)
		}
	}
	return pluginConfigs, nil
}

func pluginConfigFromYAML(pluginType, pluginName string, node *yaml.Node) (PluginConfig, error) {
	var ypc yamlPluginConfig
	if err := decodeYAMLNodeStrict(node, &ypc); err != nil {
		return PluginConfig{}, err
	}
	if ypc.PluginData != nil && ypc.PluginDataFile != nil {
		return PluginConfig{}, errors.New("only one of [pluginData, pluginDataFile] can be used")
	}

	var dataSource DataSource
	if ypc.PluginData != nil && !isEmptyYAMLNode(ypc.PluginData.Node) {
		data, err := yaml.Marshal(ypc.PluginData.Node)
		if err != nil {
			return PluginConfig{}, fmt.Errorf("failed to re-marshal plugin data: %w", err)
		}
		dataSource = FixedData{Data: string(data), Format: ConfigFormatYAML}
	}
	if ypc.PluginDataFile != nil {
		dataSource = FileData{Path: *ypc.PluginDataFile, Format: ConfigFormatYAML}
	}

	return PluginConfig{
		Name:       pluginName,
		Type:       pluginType,
		Path:       ypc.PluginCmd,
		Args:       ypc.PluginArgs,
		Checksum:   ypc.PluginChecksum,
		DataSource: dataSource,
		Disabled:   ypc.Enabled != nil && !*ypc.Enabled,
	}, nil
}

func isEmptyYAMLNode(node *yaml.Node) bool {
	return (node.Kind == yaml.MappingNode || node.Kind == yaml.SequenceNode) && len(node.Content) == 0 ||
		node.Kind == yaml.ScalarNode && node.Tag == "!!null"
}

// decodeYAMLNodeStrict decodes node into out, rejecting unknown keys.
func decodeYAMLNodeStrict(node *yaml.Node, out any) error {
	data, err := yaml.Marshal(node)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	return dec.Decode(out)
}

func stringFromToken(keyToken token.Token) (string, error) {
	if !keyToken.Type.IsIdentifier() {
		return "", fmt.Errorf("expected identifier token but got %s at %s", keyToken.Type, keyToken.Pos)
	}
	return fmt.Sprint(keyToken.Value()), nil
}
