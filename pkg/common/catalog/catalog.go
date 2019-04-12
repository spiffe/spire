package catalog

import (
	"context"

	"github.com/sirupsen/logrus"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/zeebo/errs"
)

type GlobalConfig = spi.ConfigureRequest_GlobalConfig

type Config struct {
	Log logrus.FieldLogger

	// GlobalConfig is passed to plugins during configuration.
	GlobalConfig GlobalConfig

	// PluginConfig is the configuration of plugins to load.
	PluginConfig []PluginConfig

	// KnownPlugins is the set of known external plugins.
	KnownPlugins []PluginClient

	// KnownServices is the set of known external services.
	KnownServices []ServiceClient

	// HostServices is a set of services offered by the host.
	HostServices []HostServiceServer

	// BuiltIns is the set of builtin plugins available to the host.
	BuiltIns []Plugin
}

// Catalog provides a method to obtain clients to loaded plugins and services.
type Catalog interface {
	// Fill fills up a "catalog" with client interfaces to interface with
	// the plugins and services offered by loaded plugins. The shape of the
	// "catalog" determines the constraints and requirements of the plugins.
	//
	// The "catalog" can be a pointer to an interface:
	//
	//   // Fill() will fail if there are no plugins that implement NodeAttestor
	//   var na nodeattestor.NodeAttestor
	//   cat, _ := catalog.Load(...)
	//   cat.Fill(&c)	//   catalog.Fill(&na)
	//
	// The "catalog" can also be a pointer to a struct:
	//
	//    type TheCatalog struct {
	//       // A required interface. Fill() fails if there is not exactly
	//       // one plugin matching this interface.
	//       RequiredPlugin nodeattestor.NodeAttestor
	//
	//       // An optional interface. Fill() fails if there are more than
	//       // one plugin that match this interface.
	//       OptionalPlugin *nodeattestor.NodeAttestor
	//
	//       // A slice of interfaces.
	//       Plugins []nodeattestor.NodeAttestor
	//
	//       // A map from string to interface. The key of the map is the name
	//       // of the plugin that matched.
	//       PluginsByName map[string]nodeattestor.NodeAttestor
	//
	//       // A struct of interfaces. A plugin must satisfy all interfaces //
	//       // within the struct to match. Fill() fails if there is not
	//       // exactly one plugin that matches.
	//       RequiredPluginStruct StructOfInterface
	//
	//       // A pointer to a struct of interfaces. A plugin must satisfy all
	//       // interfaces within the struct to meet the criteria. Fill() fails
	//       // if there are more than one plugin that matches.
	//       OptionalPluginStruct *StructOfInterface
	//
	//       // A slice of a struct of interfaces.
	//       PluginStructs []StructOfInterface
	//
	//       // A map from string to struct of interfaces. The key of the map
	//       // is the name of the plugin that matched.
	//       PluginStructsByName map[string]StructOfInterface
	//   }
	//
	//   type StructOfInterface struct {
	//       // The PluginInfo interface is special and is implemented on all
	//       // plugins.
	//       catalog.PluginInfo
	//
	//       nodeattestor.NodeAttestor
	//   }
	//
	//   var c TheCatalog
	//   cat, _ := catalog.Load(...)
	//   cat.Fill(&c)
	//
	//   In addition, the slice and map struct fields support imposing minimum
	//   and maximum constraints on the number of plugins to populate that
	//   field. For example:
	//
	//   struct {
	//       AtLeastTwo []nodeattestor.NodeAttestor `catalog:"min=2"`
	//       AtMostTwo []nodeattestor.NodeAttestor `catalog:"max=2"`
	//       BetweenThreeAndFive []nodeattestor.NodeAttestor `catalog:"min=3,max=5"`
	//   }
	//
	Fill(x interface{}) error

	// Close() closes the catalog, shutting down servers and killing external
	// plugin processes.
	Close()
}

type Closer interface {
	Close()
}

func Fill(ctx context.Context, config Config, x interface{}) (Closer, error) {
	c, err := Load(ctx, config)
	if err != nil {
		return nil, err
	}
	if err := c.Fill(x); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func Load(ctx context.Context, config Config) (_ Catalog, err error) {
	if config.Log == nil {
		config.Log = newDiscardingLogger()
	}

	knownPluginsMap, err := makePluginsMap(config.KnownPlugins)
	if err != nil {
		return nil, err
	}

	builtinsMap, err := makeBuiltInsMap(config.BuiltIns)
	if err != nil {
		return nil, err
	}

	// close the plugins if there is an error.
	cat := new(catalog)
	defer func() {
		if err != nil {
			cat.Close()
		}
	}()

	for _, c := range config.PluginConfig {
		// configure a logger for the plugin
		pluginLog := config.Log.WithFields(logrus.Fields{
			"name":     c.Name,
			"type":     c.Type,
			"built-in": c.Path == "",
		})

		if c.Disabled {
			pluginLog.Debug("Not loading plugin; disabled.")
			continue
		}

		var plugin *CatalogPlugin
		if c.Path == "" {
			builtin, ok := builtinsMap.Lookup(c.Name, c.Type)
			if !ok {
				return nil, errs.New("no such %s builtin %q", c.Type, c.Name)
			}
			plugin, err = LoadBuiltInPlugin(ctx, BuiltInPlugin{
				Log:          config.Log,
				Plugin:       builtin,
				HostServices: config.HostServices,
			})
		} else {
			extPlugin, ok := knownPluginsMap[c.Type]
			if !ok {
				return nil, errs.New("unknown plugin type %q", c.Type)
			}

			plugin, err = LoadExternalPlugin(ctx, ExternalPlugin{
				Log:           config.Log,
				Name:          c.Name,
				Path:          c.Path,
				Checksum:      c.Checksum,
				Plugin:        extPlugin,
				KnownServices: config.KnownServices,
				HostServices:  config.HostServices,
			})
		}
		if err != nil {
			pluginLog.Error("Failed to load plugin.")
			return nil, err
		}

		if err := plugin.Configure(ctx, &spi.ConfigureRequest{
			GlobalConfig:  &config.GlobalConfig,
			Configuration: c.Data,
		}); err != nil {
			pluginLog.Error("Failed to configure plugin.")
			return nil, errs.New("unable to configure plugin %q: %v", c.Name, err)
		}

		pluginLog.WithField("services", plugin.serviceNames).Info("Plugin loaded.")
		cat.plugins = append(cat.plugins, plugin)
	}

	return cat, nil
}

type catalog struct {
	plugins []*CatalogPlugin
}

func (c *catalog) Fill(x interface{}) (err error) {
	f := newCatalogFiller(c.plugins)
	return f.fill(x)
}

func (c *catalog) Close() {
	for _, p := range c.plugins {
		p.Close()
	}
}
