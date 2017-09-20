package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os/exec"
	"path"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/log"

	goplugin "github.com/hashicorp/go-plugin"
	pb "github.com/spiffe/spire/pkg/common/plugin"
)

type Catalog interface {
	// Run reads all config files and initializes
	// the plugins they define.
	Run() error

	// Stop terminates all plugin instances and
	// resets the catalog
	Stop()

	// Reload re-reads all plugin config files and
	// reconfigures the plugins accordingly
	Reload() error

	// Plugins returns all plugins managed by this catalog as
	// the generic Plugin type
	Plugins() []*ManagedPlugin
}

type Config struct {
	// Directory in which plugin config files
	// reside
	ConfigDir string

	SupportedPlugins map[string]goplugin.Plugin

	Log logrus.FieldLogger
}

type catalog struct {
	configDir string

	plugins          []*ManagedPlugin
	supportedPlugins map[string]goplugin.Plugin

	l logrus.FieldLogger
	m *sync.RWMutex
}

func New(config *Config) Catalog {
	return &catalog{
		configDir:        config.ConfigDir,
		supportedPlugins: config.SupportedPlugins,
		l:                config.Log,
		m:                new(sync.RWMutex),
	}
}

func (c *catalog) Run() error {
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

	err = c.configurePlugins()
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

func (c *catalog) Reload() error {
	c.m.Lock()
	defer c.m.Unlock()
	c.l.Info("Reloading plugin configurations")

	err := c.loadConfigs()
	if err != nil {
		return err
	}

	err = c.configurePlugins()
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
			ConfigPath: p.ConfigPath,
			Config:     p.Config,
			Plugin:     p.Plugin,
		}
		newSlice = append(newSlice, mp)
	}
	return newSlice
}

func (c *catalog) loadConfigs() error {
	files, err := ioutil.ReadDir(c.configDir)
	if err != nil {
		return err
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}

		p := path.Join(c.configDir, f.Name())
		err = c.loadConfig(p)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *catalog) loadConfig(path string) error {
	config, err := parsePluginConfig(path)
	if err != nil {
		return err
	}

	p := &ManagedPlugin{
		ConfigPath: path,
		Config:     config,
	}
	c.plugins = append(c.plugins, p)

	return nil
}

func (c *catalog) startPlugins() error {
	for _, p := range c.plugins {
		if !p.Config.Enabled {
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

func (c *catalog) configurePlugins() error {
	for _, p := range c.plugins {
		req := &pb.ConfigureRequest{
			Configuration: p.Config.PluginData,
		}

		c.l.Debugf("Configuring %s plugin: %s", p.Config.PluginType, p.Config.PluginName)
		_, err := p.Plugin.Configure(req)
		if err != nil {
			return fmt.Errorf("Error encountered while configuring plugin %s: %s", p.Config.PluginName, err)
		}
	}

	return nil
}

// newPluginConfig generates a go-plugin client config, given a ManagedPlugin
// struct. Useful when starting a plugin
func (c *catalog) newPluginConfig(p *ManagedPlugin) (*goplugin.ClientConfig, error) {
	// Build plugin secureConfig struct if a checksum
	// is defined
	var secureConfig *goplugin.SecureConfig
	if p.Config.PluginChecksum != "" {
		hexChecksum, err := hex.DecodeString(p.Config.PluginChecksum)
		if err != nil {
			return nil, err
		}
		secureConfig = &goplugin.SecureConfig{
			Checksum: hexChecksum,
			Hash:     sha256.New(),
		}
	} else {
		c.l.Warnf("%s plugin %s not using secure config", p.Config.PluginType, p.Config.PluginName)
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
