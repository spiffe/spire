package pluginhelper

import (
	"bytes"
	"io/ioutil"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/printer"
)

// PluginConfig is the plugin config data
type Config interface {
	ParseConfig(file string)  error
}

type PluginConfig struct {
	Version        string
	PluginName     string
	PluginCmd      string
	PluginChecksum string
	PluginData     string
	PluginType     string
	Enabled        bool
}


func (c *PluginConfig) ParseConfig(file string) error {

	result, err := parseHCLfile(file)
	if err != nil {
		return err
	}
	c.Version = result.Version
	c.PluginName = result.PluginName
	c.PluginCmd = result.PluginCmd
	c.PluginChecksum = result.PluginChecksum
	c.Enabled = result.Enabled
	c.PluginType = result.PluginType

	// Re-encode plugin-specific data
	var buf bytes.Buffer
	if err := printer.DefaultConfig.Fprint(&buf, result.PluginData); err != nil {
		return err
	}
	c.PluginData = buf.String()

	return err
}


type NodeAgentConfig struct {
	Version            string
	WorkloadAPIAddress string
}

func(c * NodeAgentConfig) ParseConfig(file string) error {
	result, err := parseHCLfile(file)
	if err != nil {
		return err
	}
	c.Version = result.Version
	c.WorkloadAPIAddress = result.WorkloadAPIAddress

	return nil
}

type ControlPlaneConfig struct {
	Version                string
	NodeAPIAddress         string
	RegistrationAPIAddress string
}

func(c * ControlPlaneConfig) ParseConfig(file string) error {
	result, err := parseHCLfile(file)
	if err != nil {
		return err
	}
	c.Version = result.Version
	c.NodeAPIAddress = result.NodeAPIAddress
	c.RegistrationAPIAddress = result.RegistrationAPIAddress


	return nil
}



// HCL config data
type HCLData struct {
	//Common config
	Version string `hcl:version`

	//Plugin Config
	PluginName     string   `hcl:pluginName`
	PluginCmd      string   `hcl:"pluginCmd"`
	PluginChecksum string   `hcl:"pluginChecksum"`
	PluginData     ast.Node `hcl:"pluginData"`
	PluginType     string   `hcl:"pluginType"`
	Enabled        bool     `hcl:enabled`

	WorkloadAPIAddress string `hcl:workloadAPIAddress`

	NodeAPIAddress         string `hcl:nodeAPIAddress`
	RegistrationAPIAddress string `hcl:registrationAPIAddress`
}

func parseHCLfile(file string) (*HCLData,error){
	hclData := &HCLData{}
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

	if err := hcl.DecodeObject(&hclData, hclParseTree); err != nil {
		return nil, err
	}
	return hclData, nil
}

