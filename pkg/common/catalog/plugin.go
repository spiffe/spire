package catalog

import (
	"bytes"

	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/printer"
	pb "github.com/spiffe/spire/proto/common/plugin"
)

type Plugin interface {
	Configure(*pb.ConfigureRequest) (*pb.ConfigureResponse, error)
	GetPluginInfo(*pb.GetPluginInfoRequest) (*pb.GetPluginInfoResponse, error)
}

type PluginConfig struct {
	Version        string `hcl:"version"`
	PluginName     string
	PluginCmd      string `hcl:"plugin_cmd"`
	PluginChecksum string `hcl:"plugin_checksum"`

	PluginData string `hcl:"plugin_data"`
	PluginType string
	Enabled    bool `hcl:"enabled"`
}

// HclPluginConfig serves as an intermediary struct. We pass this to the
// HCL library for parsing, except the parser won't parse pluginData
// as a string.
type HclPluginConfig struct {
	Version        string `hcl:"version"`
	PluginName     string
	PluginCmd      string `hcl:"plugin_cmd"`
	PluginChecksum string `hcl:"plugin_checksum"`

	PluginData ast.Node `hcl:"plugin_data"`
	PluginType string
	Enabled    bool `hcl:"enabled"`
}

type ManagedPlugin struct {
	Config PluginConfig
	Plugin Plugin
}

func parsePluginConfig(hclPluginConfig HclPluginConfig) (PluginConfig, error) {
	var pluginConfig PluginConfig
	var data bytes.Buffer

	err := printer.DefaultConfig.Fprint(&data, hclPluginConfig.PluginData)
	if err != nil {
		return pluginConfig, err
	}

	pluginConfig = PluginConfig{
		Version:        hclPluginConfig.Version,
		PluginName:     hclPluginConfig.PluginName,
		PluginCmd:      hclPluginConfig.PluginCmd,
		PluginChecksum: hclPluginConfig.PluginChecksum,
		PluginType:     hclPluginConfig.PluginType,
		Enabled:        hclPluginConfig.Enabled,

		// Handle PluginData as opaque string. This gets fed
		// to the plugin, whos job it is to parse it.
		PluginData: data.String(),
	}

	return pluginConfig, nil
}
