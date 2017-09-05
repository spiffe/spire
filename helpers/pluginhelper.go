package helpers

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os/exec"
	"path/filepath"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"

	"github.com/spiffe/sri/pkg/common/plugin"
)

type PluginCatalog struct {
	PluginConfDirectory string
	pluginTypeMap       map[string]plugin.Plugin
	maxPluginTypeMap    map[string]int
	pluginConfigs       map[string]*PluginConfig
	PluginClientsByName map[string]*PluginClients
	Logger              interface{}
}

type PluginClients struct {
	Type         string
	PluginClient interface{}
}

type Plugin interface {
	Configure(*sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error)
	GetPluginInfo(*sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error)
}

func (c *PluginCatalog) loadConfig() (err error) {
	c.pluginConfigs = make(map[string]*PluginConfig)
	PluginTypeCount := make(map[string]int)
	configFiles, err := ioutil.ReadDir(c.PluginConfDirectory)
	if err != nil {
		return err
	}

	for _, configFile := range configFiles {
		pluginConfig := &PluginConfig{}
		err := pluginConfig.ParseConfig(filepath.Join(
			c.PluginConfDirectory, configFile.Name()))
		if err != nil {
			return err
		}
		PluginTypeCount[pluginConfig.PluginType] = +1
		if PluginTypeCount[pluginConfig.PluginType] > c.maxPluginTypeMap[pluginConfig.PluginType] {
			return errors.New(fmt.Sprintf("Cannot have more than max_plugins:%v plugins of type plugin_type:%v",
				c.maxPluginTypeMap[pluginConfig.PluginType], pluginConfig.PluginType))
		}

		if c.pluginTypeMap[pluginConfig.PluginType] == nil {
			return errors.New(fmt.Sprintf("PluginClient Type plugin_type:%v not supported", pluginConfig.PluginType))
		}

		if c.pluginConfigs[pluginConfig.PluginName] != nil {
			return errors.New(fmt.Sprintf("plugin_name:%s should be unique", pluginConfig.PluginName))
		}
		c.pluginConfigs[pluginConfig.PluginName] = pluginConfig

	}
	return err
}

func (c *PluginCatalog) SetPluginTypeMap(pluginTypeMap map[string]plugin.Plugin) {
	c.pluginTypeMap = pluginTypeMap
}

func (c *PluginCatalog) SetMaxPluginTypeMap(maxPluginMap map[string]int) {
	c.maxPluginTypeMap = maxPluginMap
}

func (c *PluginCatalog) GetPluginByName(pluginName string) (pluginClient interface{}) {
	pluginClient = c.PluginClientsByName[pluginName].PluginClient
	return
}

func (c *PluginCatalog) GetPluginsByType(typeName string) (pluginClients []interface{}) {
	for _, clients := range c.PluginClientsByName {
		if clients.Type == typeName {
			pluginClients = append(pluginClients, clients.PluginClient)
		}
	}
	return
}

func (c *PluginCatalog) initClients() (err error) {

	c.PluginClientsByName = make(map[string]*PluginClients)
	for _, pluginconfig := range c.pluginConfigs {

		if pluginconfig.Enabled {

			var secureConfig *plugin.SecureConfig
			if pluginconfig.PluginChecksum != "" {
				hexChecksum, err := hex.DecodeString(pluginconfig.PluginChecksum)
				if err != nil {
					return err
				}
				secureConfig = &plugin.SecureConfig{
					Checksum: hexChecksum,
					Hash:     sha256.New(),
				}
			}

			client := plugin.NewClient(&plugin.ClientConfig{

				HandshakeConfig: plugin.HandshakeConfig{
					ProtocolVersion:  1,
					MagicCookieKey:   pluginconfig.PluginType,
					MagicCookieValue: pluginconfig.PluginType,
				},

				Plugins: map[string]plugin.Plugin{
					pluginconfig.PluginName: plugin.Plugin(c.pluginTypeMap[pluginconfig.PluginType]),
				},

				Cmd: exec.Command(pluginconfig.PluginCmd),

				AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},

				Managed: true,

				SecureConfig: secureConfig,

				Logger: c.Logger.(hclog.Logger),
			})

			protocolClient, err := client.Client()
			if err != nil {
				return err
			}

			pl, err := protocolClient.Dispense(pluginconfig.PluginName)
			if err != nil {
				return err
			}

			c.PluginClientsByName[pluginconfig.PluginName] = &PluginClients{
				c.pluginConfigs[pluginconfig.PluginName].PluginType, pl}

		}
	}
	return
}

func (c *PluginCatalog) ConfigureClients() error {
	for _, config := range c.pluginConfigs {
		p := c.GetPluginByName(config.PluginName).(Plugin)

		req := &sriplugin.ConfigureRequest{
			Configuration: config.PluginData,
		}
		_, err := p.Configure(req)
		if err != nil {
			return fmt.Errorf("Error encountered while configuring plugin %s: %s", config.PluginName, err)
		}
	}

	return nil
}

func (c *PluginCatalog) Run() (err error) {
	err = c.loadConfig()
	if err != nil {
		return err
	}

	err = c.initClients()
	if err != nil {
		return err
	}

	err = c.ConfigureClients()
	if err != nil {
		return err
	}

	return nil
}

func (c *PluginCatalog) Stop() {
	plugin.CleanupClients()
}
