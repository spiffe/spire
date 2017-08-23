package helpers

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os/exec"
	"path/filepath"

	"github.com/hashicorp/go-plugin"
)

type PluginCatalog struct {
	PluginConfDirectory string
	PluginTypeMap       map[string]plugin.Plugin
	PluginConfigs       map[string]*PluginConfig
	PluginClients       map[string]*plugin.Client
	Plugins             map[string]interface{}
	MaxPluginTypeMap    map[string]int
}

func (c *PluginCatalog) loadConfig() (err error) {
	c.PluginConfigs = make(map[string]*PluginConfig)
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
		if PluginTypeCount[pluginConfig.PluginType] > c.MaxPluginTypeMap[pluginConfig.PluginType] {
			return errors.New(fmt.Sprintf("Cannot have more than max_plugins:%v plugins of type plugin_type:%v",
				c.MaxPluginTypeMap[pluginConfig.PluginType], pluginConfig.PluginType))
		}

		if c.PluginTypeMap[pluginConfig.PluginType] == nil {
			return errors.New(fmt.Sprintf("Plugin Type plugin_type:%v not supported", pluginConfig.PluginType))
		}

		if c.PluginConfigs[pluginConfig.PluginName] != nil {
			return errors.New(fmt.Sprintf("plugin_name:%s should be unique", pluginConfig.PluginName))
		}
		c.PluginConfigs[pluginConfig.PluginName] = pluginConfig

	}
	return err
}

func (c *PluginCatalog) SetPluginTypeMap(pluginTypeMap map[string]plugin.Plugin) {
	c.PluginTypeMap = pluginTypeMap
}

func (c *PluginCatalog) SetMaxPluginTypeMap(maxPluginMap map[string]int) {
	c.MaxPluginTypeMap = maxPluginMap
}

func (c *PluginCatalog) GetPlugin(pluginName string) (plugin interface{}) {
	plugin = c.Plugins[pluginName]
	return
}

func (c *PluginCatalog) initClients() (err error) {

	c.PluginClients = make(map[string]*plugin.Client)

	for _, pluginconfig := range c.PluginConfigs {
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
					pluginconfig.PluginName: plugin.Plugin(
						c.PluginTypeMap[pluginconfig.PluginType]),
				},
				Cmd:              exec.Command(pluginconfig.PluginCmd),
				AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
				Managed:          true,
				SecureConfig:     secureConfig,
			})

			c.PluginClients[pluginconfig.PluginName] = client
		}
	}
	return
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
	c.Plugins = make(map[string]interface{})
	for pluginName, client := range c.PluginClients {
		protocolClient, err := client.Client()
		if err != nil {
			return err
		}
		fmt.Print("PluginName:")
		fmt.Print(pluginName)
		pl, err := protocolClient.Dispense(pluginName)
		if err != nil {
			return err
		}
		c.Plugins[pluginName] = pl
	}
	return
}
