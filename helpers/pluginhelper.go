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
	"github.com/sirupsen/logrus"

	"github.com/spiffe/spire/pkg/common/plugin"
)

type PluginCatalogImpl struct {
	pluginTypeMap       map[string]plugin.Plugin
	maxPluginTypeMap    map[string]int
	pluginConfigs       map[string]*PluginConfig
	PluginClientsByName map[string]*PluginClients
	pcc                 *PluginCatalogConfig
}

func NewPluginCatalog(cc *PluginCatalogConfig) (pc *PluginCatalogImpl) {
	pc = &PluginCatalogImpl{pcc: cc}
	return
}

type PluginCatalogConfig struct {
	PluginConfDirectory string
	Logger              *logrus.Entry
}

type PluginClients struct {
	Type         string
	PluginClient interface{}
}

type Plugin interface {
	Configure(*sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error)
	GetPluginInfo(*sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error)
}

func (c *PluginCatalogImpl) loadConfig() (err error) {
	c.pluginConfigs = make(map[string]*PluginConfig)
	PluginTypeCount := make(map[string]int)
	configFiles, err := ioutil.ReadDir(c.pcc.PluginConfDirectory)
	if err != nil {
		return err
	}

	for _, configFile := range configFiles {
		pluginConfig := &PluginConfig{}
		err := pluginConfig.ParseConfig(filepath.Join(
			c.pcc.PluginConfDirectory, configFile.Name()))
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

func (c *PluginCatalogImpl) SetPluginTypeMap(pluginTypeMap map[string]plugin.Plugin) {
	c.pluginTypeMap = pluginTypeMap
}

func (c *PluginCatalogImpl) SetMaxPluginTypeMap(maxPluginMap map[string]int) {
	c.maxPluginTypeMap = maxPluginMap
}

func (c *PluginCatalogImpl) GetPluginByName(pluginName string) (pluginClient interface{}) {
	pluginClient = c.PluginClientsByName[pluginName].PluginClient
	return
}

func (c *PluginCatalogImpl) GetPluginsByType(typeName string) (pluginClients []interface{}) {
	for _, clients := range c.PluginClientsByName {
		if clients.Type == typeName {
			pluginClients = append(pluginClients, clients.PluginClient)
		}
	}
	return
}
func (c *PluginCatalogImpl) GetAllPlugins() (pluginClients map[string]*PluginClients) {
	pluginClients = c.PluginClientsByName
	return

}

func (c *PluginCatalogImpl) initClients() (err error) {

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

				Logger: &HCLogAdapter{Log: c.pcc.Logger, Name: "plugin"},
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

func (c *PluginCatalogImpl) ConfigureClients() error {
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

func (c *PluginCatalogImpl) Run() (err error) {
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

func (c *PluginCatalogImpl) Stop() {
	plugin.CleanupClients()
}
