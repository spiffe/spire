package helpers

import (
	"bytes"
	"io/ioutil"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/printer"
)

// PluginConfig is the plugin config data
type Config interface {
	LogConfig() (logFile string, logLevel string)
	ParseConfig(file string) error
	setConfig(data interface{}) error
}

type PluginConfig struct {
	Version        string
	PluginName     string
	PluginCmd      string
	PluginChecksum string
	PluginData     string
	PluginType     string
	Enabled        bool
	logFile        string
	logLevel       string
}

func (c *PluginConfig) LogConfig() (logFile string, logLevel string) {
	return c.logFile, c.logLevel
}

func (c *PluginConfig) ParseConfig(file string) (err error) {

	result, err := parseHCLfile(file)
	if err != nil {
		return err
	}
	c.setConfig(result)
	if err != nil {
		return err
	}
	return err
}

func (c *PluginConfig) setConfig(data interface{}) error {
	hclData := data.(*HCLData)
	c.Version = hclData.Version
	c.PluginName = hclData.PluginName
	c.PluginCmd = hclData.PluginCmd
	c.PluginChecksum = hclData.PluginChecksum
	c.Enabled = hclData.Enabled
	c.PluginType = hclData.PluginType
	c.logFile = hclData.LogFile
	c.logLevel = hclData.LogLevel

	// Re-encode plugin-specific data
	var buf bytes.Buffer
	if err := printer.DefaultConfig.Fprint(&buf, hclData.PluginData); err != nil {
		return err
	}
	c.PluginData = buf.String()
	return nil
}

type NodeAgentConfig struct {
	Version            string
	WorkloadAPIAddress string
	logFile            string
	logLevel           string
}

func (c *NodeAgentConfig) LogConfig() (logFile string, logLevel string) {
	return c.logFile, c.logLevel
}

func (c *NodeAgentConfig) ParseConfig(file string) error {
	result, err := parseHCLfile(file)
	if err != nil {
		return err
	}
	if err = c.setConfig(result); err != nil {
		return err
	}
	return nil
}

func (c *NodeAgentConfig) setConfig(data interface{}) error {
	hclData := data.(*HCLData)
	c.Version = hclData.Version
	c.WorkloadAPIAddress = hclData.WorkloadAPIAddress
	c.logFile = hclData.LogFile
	c.logLevel = hclData.LogLevel

	return nil
}

type ControlPlaneConfig struct {
	Version                 string
	TrustDomain             string
	NodeAPIGRPCPort         string
	RegistrationAPIGRPCPort string
	NodeAPIHTTPPort         string
	RegistrationAPIHTTPPort string
	BaseSpiffeIDTTL         int32
	logFile                 string
	logLevel                string
    ServerHTTPAddr          string
    ServerGRPCAddr          string
}

func (c *ControlPlaneConfig) LogConfig() (logFile string, logLevel string) {
	return c.logFile, c.logLevel
}

func (c *ControlPlaneConfig) ParseConfig(file string) error {
	result, err := parseHCLfile(file)
	if err != nil {
		return err
	}
	if err = c.setConfig(result); err != nil {
		return err
	}
	return nil
}

func (c *ControlPlaneConfig) setConfig(data interface{}) error {
	hclData := data.(*HCLData)

	c.Version = hclData.Version
	c.TrustDomain = hclData.TrustDomain
	c.NodeAPIGRPCPort = hclData.NodeAPIGRPCPort
	c.RegistrationAPIGRPCPort = hclData.RegistrationAPIGRPCPort
	c.NodeAPIGRPCPort = hclData.NodeAPIGRPCPort
	c.RegistrationAPIGRPCPort = hclData.RegistrationAPIGRPCPort

	c.logLevel = hclData.LogLevel
	c.logFile = hclData.LogFile

	c.ServerHTTPAddr = hclData.ServerHTTPAddr
	c.ServerGRPCAddr = hclData.ServerGRPCAddr

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
	LogFile        string   `hcl:logFile`
	LogLevel       string   `hcl:logLevel`

	WorkloadAPIAddress string `hcl:workloadAPIAddress`

	TrustDomain             string `hcl:trustDomain`
	NodeAPIGRPCPort         string `hcl:nodeAPIGRPCPort`
	RegistrationAPIGRPCPort string `hcl:registrationAPIGRPCPort`
	NodeAPIHTTPPort         string `hcl:nodeAPIHTTPPort`
	RegistrationAPIHTTPPort string `hcl:registrationAPIHTTPPort`

	ServerHTTPAddr string `hcl:serverHTTPAddr`
	ServerGRPCAddr string `hcl:serverGRPCAddr`
}

func parseHCLfile(file string) (*HCLData, error) {
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
