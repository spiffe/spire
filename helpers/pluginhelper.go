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
	"github.com/spiffe/node-agent/plugins/key_manager"
	"github.com/spiffe/node-agent/plugins/node_attestor"
	"github.com/spiffe/node-agent/plugins/workload_attestor"
)

/*var NA_PLUGIN_TYPE_MAP = map[string]plugin.Plugin{
	"WorkloadAttestor": &workloadattestor.WorkloadAttestorPlugin{},
	"KeyManager":       &keymanager.KeyManagerPlugin{},
	"NodeAttestor":     &nodeattestor.NodeAttestorPlugin{},
}*/

type PluginCatalog struct {
	PluginConfDirectory string
	PluginConfigs       map[string]*PluginConfig
	PluginClients       map[string]*plugin.Client
	Plugins             map[string]interface{}
}

func (c *PluginCatalog) loadConfig() (err error) {
	c.PluginConfigs = make(map[string]*PluginConfig)
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
		if c.PluginConfigs[config.PluginName] != nil {
			return errors.New(fmt.Sprintf("PluginName:%s should be unique", config.PluginName))
		}
		c.PluginConfigs[config.PluginName] = config

	}
	return err
}

func (c *PluginCatalog) GetPlugin(pluginName string) (plugin interface{}) {
	plugin = c.Plugins[pluginName]
	return
}

func (c *PluginCatalog) initClients(pluginMap map[string]plugin.Plugin) (err error) {

	c.PluginClients = make(map[string]*plugin.Client)

	for _, pluginconfig := range c.PluginConfigs {
		if pluginconfig.Enabled {
			hexChecksum, err := hex.DecodeString(pluginconfig.PluginChecksum)
			if err != nil {
				return err
			}

			client := plugin.NewClient(&plugin.ClientConfig{
				HandshakeConfig: plugin.HandshakeConfig{
					ProtocolVersion:  1,
					MagicCookieKey:   pluginconfig.PluginType,
					MagicCookieValue: pluginconfig.PluginType,
				},
				Plugins: map[string]plugin.Plugin{
					pluginconfig.PluginName: plugin.Plugin(
						pluginMap[pluginconfig.PluginType]),
				},
				Cmd:              exec.Command(pluginconfig.PluginCmd),
				AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
				Managed:          true,
				SecureConfig: &plugin.SecureConfig{Checksum: hexChecksum,
					Hash: sha256.New()},
			})

			c.PluginClients[pluginconfig.PluginName] = client
		}
	}
	return
}

func (c *PluginCatalog) Run(pluginMap map[string]plugin.Plugin) (err error) {
	err = c.loadConfig()
	if err != nil {
		return err
	}
	err = c.initClients(pluginMap)
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
		}

	}
	return
}
