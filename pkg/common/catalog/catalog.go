package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/log"

	goplugin "github.com/hashicorp/go-plugin"
	pb "github.com/spiffe/spire/proto/common/plugin"
)

type Catalog interface {
	// Run reads all config files and initializes
	// the plugins they define.
	Run(ctx context.Context) error

	// Stop terminates all plugin instances and
	// resets the catalog
	Stop()

	// Reload re-reads all plugin config files and
	// reconfigures the plugins accordingly
	Reload(ctx context.Context) error

	// Plugins returns all plugins managed by this catalog as
	// the generic Plugin type
	Plugins() []*ManagedPlugin

	// ConfigFor finds the plugin configuration for the supplied plugin. nil
	// is returned if the plugin is not managed by the catalog.
	ConfigFor(interface{}) *PluginConfig
}

type Config struct {
	PluginConfigs    PluginConfigMap
	SupportedPlugins map[string]goplugin.Plugin
	BuiltinPlugins   BuiltinPluginMap
	Log              logrus.FieldLogger
}

type catalog struct {
	pluginConfigs    PluginConfigMap
	plugins          []*ManagedPlugin
	supportedPlugins map[string]goplugin.Plugin
	builtinPlugins   BuiltinPluginMap

	l logrus.FieldLogger
	m *sync.RWMutex
}

// BuiltinPluginMap organizes builtin plugin sets, accessed by
// [plugin type][plugin name]
type BuiltinPluginMap map[string]map[string]Plugin

// PluginConfigMap maps plugin configurations, accessed by
// [plugin type][plugin name]
type PluginConfigMap map[string]map[string]HclPluginConfig

func New(config *Config) Catalog {
	return &catalog{
		pluginConfigs:    config.PluginConfigs,
		supportedPlugins: config.SupportedPlugins,
		builtinPlugins:   config.BuiltinPlugins,
		l:                config.Log,
		m:                new(sync.RWMutex),
	}
}

func (c *catalog) Run(ctx context.Context) error {
	c.m.Lock()
	defer c.m.Unlock()
	c.l.Info("Starting plugin catalog")

	if c.plugins != nil {
		return errors.New("plugins have already been started")
	}

	err := c.loadConfigs()
	if err != nil {
		return err
	}

	err = c.startPlugins()
	if err != nil {
		return err
	}

	err = c.configurePlugins(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (c *catalog) Stop() {
	c.m.Lock()
	defer c.m.Unlock()
	c.l.Info("Stopping plugin catalog")

	goplugin.CleanupClients()
	c.plugins = []*ManagedPlugin{}
	return
}

func (c *catalog) Reload(ctx context.Context) error {
	c.m.Lock()
	defer c.m.Unlock()
	c.l.Info("Reloading plugin configurations")

	err := c.loadConfigs()
	if err != nil {
		return err
	}

	err = c.configurePlugins(ctx)
	if err != nil {
		return err
	}

	return nil
}

// Plugins takes a read lock to ensure consistency in our
// plugin records, and then returns a copy of `plugins`
func (c *catalog) Plugins() []*ManagedPlugin {
	c.m.RLock()
	defer c.m.RUnlock()

	var newSlice []*ManagedPlugin
	for _, p := range c.plugins {
		mp := &ManagedPlugin{
			Config: p.Config,
			Plugin: p.Plugin,
		}
		newSlice = append(newSlice, mp)
	}
	return newSlice
}

func (c *catalog) ConfigFor(plugin interface{}) *PluginConfig {
	c.m.RLock()
	defer c.m.RUnlock()

	for _, p := range c.plugins {
		if p.Plugin == plugin {
			config := p.Config
			return &config
		}
	}
	return nil
}

func (c *catalog) loadConfigs() error {
	for pluginType, plugins := range c.pluginConfigs {
		for pluginName, pluginConfig := range plugins {
			pluginConfig.PluginType = pluginType
			pluginConfig.PluginName = pluginName
			err := c.loadConfigFromHclConfig(pluginConfig)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *catalog) loadConfigFromHclConfig(hclPluginConfig HclPluginConfig) error {
	config, err := parsePluginConfig(hclPluginConfig)
	if err != nil {
		return err
	}

	p := &ManagedPlugin{
		Config: config,
	}
	c.plugins = append(c.plugins, p)

	return nil
}

func (c *catalog) startPlugins() error {
	for _, p := range c.plugins {
		if !p.Config.Enabled {
			c.l.Debugf("%s plugin %s is disabled and will not be started", p.Config.PluginType, p.Config.PluginName)
			continue
		}

		builtin := c.builtins(p.Config.PluginType, p.Config.PluginName)
		if builtin != nil {
			p.Plugin = builtin
			continue
		}

		config, err := c.newPluginConfig(p)
		if err != nil {
			return err
		}

		c.l.Debugf("Starting %s plugin: %s", p.Config.PluginType, p.Config.PluginName)
		client, err := goplugin.NewClient(config).Client()
		if err != nil {
			return err
		}

		raw, err := client.Dispense(p.Config.PluginName)
		if err != nil {
			return err
		}

		var ok bool
		p.Plugin, ok = raw.(Plugin)
		if !ok {
			return fmt.Errorf("Plugin %s does not conform to the plugin interface", p.Config.PluginName)
		}
	}

	return nil
}

func (c *catalog) configurePlugins(ctx context.Context) error {
	for _, p := range c.plugins {
		if !p.Config.Enabled {
			c.l.Debugf("%s plugin %s is disabled and will not be configured", p.Config.PluginType, p.Config.PluginName)
			continue
		}

		req := &pb.ConfigureRequest{
			Configuration: p.Config.PluginData,
		}

		c.l.Debugf("Configuring %s plugin: %s", p.Config.PluginType, p.Config.PluginName)
		_, err := p.Plugin.Configure(ctx, req)
		if err != nil {
			return fmt.Errorf("Error encountered while configuring plugin %s: %s", p.Config.PluginName, err)
		}
	}

	return nil
}

// newPluginConfig generates a go-plugin client config, given a ManagedPlugin
// struct. Useful when starting a plugin
func (c *catalog) newPluginConfig(p *ManagedPlugin) (*goplugin.ClientConfig, error) {
	secureConfig, err := c.secureConfig(p)
	if err != nil {
		return nil, err
	}

	// Build go-plugin client config struct
	pluginType, ok := c.supportedPlugins[p.Config.PluginType]
	if !ok {
		return nil, fmt.Errorf("Plugin type %s is unsupported", p.Config.PluginType)
	}
	pluginMap := map[string]goplugin.Plugin{
		p.Config.PluginName: pluginType,
	}
	l := c.l.WithField("plugin_type", p.Config.PluginType)
	l = l.WithField("plugin_name", p.Config.PluginName)

	config := &goplugin.ClientConfig{
		HandshakeConfig: goplugin.HandshakeConfig{
			ProtocolVersion:  1,
			MagicCookieKey:   p.Config.PluginType,
			MagicCookieValue: p.Config.PluginType,
		},
		Plugins:          pluginMap,
		Cmd:              exec.Command(p.Config.PluginCmd),
		AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC},
		Managed:          true,
		SecureConfig:     secureConfig,
		Logger:           &log.HCLogAdapter{Log: l, Name: "plugin"},
	}

	return config, nil
}

func (c *catalog) secureConfig(p *ManagedPlugin) (*goplugin.SecureConfig, error) {
	if p.Config.PluginChecksum == "" {
		c.l.Warnf("%s plugin %s not using secure config", p.Config.PluginType, p.Config.PluginName)
		return nil, nil
	}

	sum, err := hex.DecodeString(p.Config.PluginChecksum)
	if err != nil {
		return nil, fmt.Errorf("decode plugin hash: %v", err)
	}

	config := &goplugin.SecureConfig{
		Checksum: sum,
		Hash:     sha256.New(),
	}

	return config, nil
}

// builtins determines, given a configured plugin's name and type, if it is an
// available builtin. Returns nil if it is not.
func (c *catalog) builtins(pType, pName string) Plugin {
	plugins, ok := c.builtinPlugins[pType]
	if !ok {
		return nil
	}

	plugin, ok := plugins[pName]
	if !ok {
		return nil
	}

	return plugin
}
