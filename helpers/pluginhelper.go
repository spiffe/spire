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
	"github.com/spiffe/sri/control_plane/plugins/control_plane_ca"
	"github.com/spiffe/sri/control_plane/plugins/data_store"
//      "github.com/spiffe/sri/control_plane/plugins/node_attestor"
	"github.com/spiffe/sri/control_plane/plugins/node_resolver"
    "github.com/spiffe/sri/control_plane/plugins/upstream_ca"
//    "github.com/spiffe/sri/node_agent/plugins/key_manager"
    "github.com/spiffe/sri/node_agent/plugins/node_attestor"
//    "github.com/spiffe/sri/node_agent/plugins/workload_attestor"
)

var NA_PLUGIN_TYPE_MAP = map[string]plugin.Plugin{
	"ControlPlaneCA": &controlplaneca.ControlPlaneCaPlugin{},
	"DataStore":      &datastore.DataStorePlugin{},
	"NodeAttestor":   &nodeattestor.NodeAttestorPlugin{},
	"NodeResolver":   &noderesolver.NodeResolutionPlugin{},
	"UpstreamCA":     &upstreamca.UpstreamCaPlugin{},
}

var MaxPlugins = map[string]int{
	"ControlPlaneCA": 1,
	"DataStore":      1,
	"NodeAttestor":   1,
	"NodeResolver":   1,
	"UpstreamCA":     1,
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
		fmt.Print("PluginName:")
		fmt.Print(pluginName)
		pl, err := protocolClient.Dispense(pluginName)
		if err != nil {
			return err
		}

		switch pl.(type) {
		case controlplaneca.ControlPlaneCa:
			c.Plugins[pluginName] = pl.(controlplaneca.ControlPlaneCa)
		case datastore.DataStore:
			c.Plugins[pluginName] = pl.(datastore.DataStore)
		case nodeattestor.NodeAttestor:
			c.Plugins[pluginName] = pl.(nodeattestor.NodeAttestor)
		case noderesolver.NodeResolution:
			c.Plugins[pluginName] = pl.(noderesolver.NodeResolution)
		case upstreamca.UpstreamCa:
			c.Plugins[pluginName] = pl.(upstreamca.UpstreamCa)

		default:
			return errors.New(fmt.Sprintf("Plugin Unsupported pluginType:%v", reflect.TypeOf(pl)))
		}

	}
	return
}
