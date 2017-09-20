package catalog

import (
	"bytes"

	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/printer"
	"github.com/spiffe/spire/pkg/common/config"

	pb "github.com/spiffe/spire/pkg/common/plugin"
)

type Plugin interface {
	Configure(*pb.ConfigureRequest) (*pb.ConfigureResponse, error)
	GetPluginInfo(*pb.GetPluginInfoRequest) (*pb.GetPluginInfoResponse, error)
}

type PluginConfig struct {
	Version        string `hcl:version`
	PluginName     string `hcl:pluginName`
	PluginCmd      string `hcl:pluginCmd`
	PluginChecksum string `hcl:pluginChecksum`

	PluginData string `hcl:pluginData`
	PluginType string `hcl:pluginType`
	Enabled    bool   `hcl:enabled`
}

// hclPluginConfig serves as an intermediary struct. We pass this to the
// HCL library for parsing, except the parser won't parse pluginData
// as a string.
type hclPluginConfig struct {
	Version        string `hcl:version`
	PluginName     string `hcl:pluginName`
	PluginCmd      string `hcl:pluginCmd`
	PluginChecksum string `hcl:pluginChecksum`

	PluginData ast.Node `hcl:pluginData`
	PluginType string   `hcl:pluginType`
	Enabled    bool     `hcl:enabled`
}

type ManagedPlugin struct {
	ConfigPath string

	Config PluginConfig
	Plugin Plugin
}

func parsePluginConfig(path string) (PluginConfig, error) {
	var pluginConfig PluginConfig

	c := new(hclPluginConfig)
	err := config.ParseHCLFile(path, &c)
	if err != nil {
		return pluginConfig, err
	}

	// Handle PluginData as opaque string. This gets fed
	// to the plugin, whos job it is to parse it.
	var data bytes.Buffer
	err = printer.DefaultConfig.Fprint(&data, c.PluginData)
	if err != nil {
		return pluginConfig, err
	}

	pluginConfig = PluginConfig{
		Version:        c.Version,
		PluginName:     c.PluginName,
		PluginCmd:      c.PluginCmd,
		PluginChecksum: c.PluginChecksum,
		PluginType:     c.PluginType,
		Enabled:        c.Enabled,

		PluginData: data.String(),
	}

	return pluginConfig, nil
}
