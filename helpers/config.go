package helpers

import (
	"bytes"
	"io/ioutil"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/printer"
)

// PluginConfig is the plugin config data
type PluginConfig struct {
	PluginName     string
	PluginCmd      string
	PluginChecksum string
	PluginData     string
	PluginType     string
	Enabled        bool
}

// HCL config data
type config struct {
	PluginName     string   `hcl:pluginName`
	PluginCmd      string   `hcl:"pluginCmd"`
	PluginChecksum string   `hcl:"pluginChecksum"`
	PluginData     ast.Node `hcl:"pluginData"`
	PluginType     string   `hcl:"pluginType"`
	Enabled        bool     `hcl:enabled`
}

// ParseConfig parses the given HCL file into a PluginConfig struct
func ParseConfig(file string) (*PluginConfig, error) {
	result := &config{}
	var errors *multierror.Error

	// Read HCL file
	dat, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	hclText := string(dat)

	// Parse HCL
	hclParseTree, err := hcl.Parse(hclText)
	if err != nil {
		return nil, err
	}

	if err := hcl.DecodeObject(&result, hclParseTree); err != nil {
		return nil, err
	}

	res := &PluginConfig{}
	res.PluginName = result.PluginName
	res.PluginCmd = result.PluginCmd
	res.PluginChecksum = result.PluginChecksum
	res.Enabled = result.Enabled
	res.PluginType = result.PluginType

	// Re-encode plugin-specific data
	var buf bytes.Buffer
	if err := printer.DefaultConfig.Fprint(&buf, result.PluginData); err != nil {
		return nil, err
	}
	res.PluginData = buf.String()

	return res, errors.ErrorOrNil()
}
