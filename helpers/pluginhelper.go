package pluginhelper

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"reflect"

	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/node-agent/plugins/key_manager"
	"github.com/spiffe/node-agent/plugins/node_attestor"
	"github.com/spiffe/node-agent/plugins/workload_attestor"
)

var NA_PLUGIN_TYPE_MAP = map[string]plugin.Plugin{
	"WorkloadAttestor": &workloadattestor.WorkloadAttestorPlugin{},
	"KeyManager":       &keymanager.KeyManagerPlugin{},
	"NodeAttestor":     &nodeattestor.NodeAttestorPlugin{},
}

var MaxPlugins = map[string]int{
	"WorkloadAttestor": 1,
	"KeyManager":       1,
	"NodeAttestor":     1,
}

type PluginCatalog struct {
	PluginConfDirectory string
	PluginConfigs       map[string]*PluginConfig
	PluginClients       map[string]*plugin.Client
	Plugins             map[string]interface{}
}

func (c *PluginCatalog) loadConfig() (err error) {
	c.PluginConfigs = make(map[string]*PluginConfig)
	PluginTypeCount := make(map[string]int)
	configFiles, err := ioutil.ReadDir(c.PluginConfDirectory)
	if err != nil {
		return err
	}

	for _, configFile := range configFiles {
		config, err := ParseConfig(filepath.Join(
			c.PluginConfDirectory, configFile.Name()))
		if err != nil {
			return err
		}
		PluginTypeCount[config.PluginType] = +1
		if PluginTypeCount[config.PluginType] > MaxPlugins[config.PluginType] {
			return errors.New(fmt.Sprintf("Cannot have more than max_plugins:%v plugins of type plugin_type:%v",
				MaxPlugins[config.PluginType], config.PluginType))
		}

		if NA_PLUGIN_TYPE_MAP[config.PluginType] == nil {
			return errors.New(fmt.Sprintf("Plugin Type plugin_type:%v not supported", config.PluginType))
		}

		if c.PluginConfigs[config.PluginName] != nil {
			return errors.New(fmt.Sprintf("plugin_name:%s should be unique", config.PluginName))
		}
		c.PluginConfigs[config.PluginName] = config

	}
	return err
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
						NA_PLUGIN_TYPE_MAP[pluginconfig.PluginType]),
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
		pl, err := protocolClient.Dispense(pluginName)
		if err != nil {
			return err
		}

		switch pl.(type) {
		case nodeattestor.NodeAttestor:
			c.Plugins[pluginName] = pl.(nodeattestor.NodeAttestor)
		case workloadattestor.WorkloadAttestor:
			c.Plugins[pluginName] = pl.(workloadattestor.WorkloadAttestor)
		case keymanager.KeyManager:
			c.Plugins[pluginName] = pl.(keymanager.KeyManager)
		default:
			return errors.New(fmt.Sprintf("Plugin Unsupported pluginType:%v", reflect.TypeOf(pl).Name()))
		}

	}
	return
}
