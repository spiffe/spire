package catalog

import (
	"context"
	"fmt"
	"io"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/private"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"google.golang.org/grpc"
)

// Catalog is a set of plugin and service repositories.
type Catalog interface {
	// Plugins returns a map of plugin repositories, keyed by the plugin type.
	Plugins() map[string]PluginRepo

	// Services returns service repositories.
	Services() []ServiceRepo
}

// PluginRepo is a repository of plugin facades for a given plugin type.
type PluginRepo interface {
	ServiceRepo

	// Constraints returns the constraints required by the plugin repository.
	// The Load function will ensure that these constraints are satisfied before
	// returning successfully.
	Constraints() Constraints

	// BuiltIns provides the list of built ins that are available for the
	// given plugin repository.
	BuiltIns() []BuiltIn
}

// ServiceRepo is a repository for service facades for a given service.
type ServiceRepo interface {
	// Binder returns a function that is used by the catalog system to "bind"
	// the facade returned by selected version to the repository. It MUST
	// return void and take a single argument of type X, where X can be
	// assigned to by any of the facade implementation types returned by the
	// provided versions (see Versions).
	Binder() any

	// Versions returns the versions supported by the repository, ordered by
	// most to least preferred. The first version supported by the plugin will
	// be used. When a deprecated version is bound, warning messaging will
	// recommend the first version in the list as a replacement, unless it is
	// also deprecated.
	Versions() []Version

	// Clear is called when loading fails to clear the repository of any
	// previously bound facades.
	Clear()
}

// Version represents a plugin or service version. It is used to instantiate
// facades for the versions that are bound to the plugin or service
// repositories (see the Binder method on the ServiceRepo).
type Version interface {
	// New returns a new facade for this version. Instantiated facades are only
	// bound via the repo binder when they match a gRPC service name provided
	// by the plugin.
	New() Facade

	// Deprecated returns whether or not the version is deprecated.
	Deprecated() bool
}

// Facade is a facade for a specific plugin or service version.
type Facade interface {
	// ServiceClient is used to initialize the service client with the
	// connection to the plugin providing the service server.
	pluginsdk.ServiceClient

	// InitInfo is used to initialize the facade with information for the
	// loaded plugin providing the service server.
	InitInfo(info PluginInfo)

	// InitLog initializes the facade with the logger for the loaded plugin
	// that provides the service server.
	InitLog(log logrus.FieldLogger)
}

// PluginInfo provides the information for the loaded plugin.
type PluginInfo interface {
	// The name of the plugin (e.g. "aws_iid").
	Name() string

	// The type of the plugin (e.g. KeyManager).
	Type() string
}

type Config struct {
	// Log is the logger. It is used for general purpose logging and also
	// provided to the plugins.
	Log logrus.FieldLogger

	// PluginConfigs is the list of plugin configurations.
	PluginConfigs []PluginConfig

	// HostServices are the servers for host services provided by SPIRE to
	// plugins.
	HostServices []pluginsdk.ServiceServer

	// CoreConfig is the core configuration provided to each plugin.
	CoreConfig CoreConfig
}

// Load loads and configures plugins defined in the configuration. The given
// catalog is populated with plugin and service facades for versions
// implemented by the loaded plugins. The returned io.Closer can be used to
// close down the loaded plugins, at which point, all facades bound to the
// given catalog are considered invalidated. If any plugin fails to load or
// configure, all plugins are unloaded, the catalog is cleared, and the
// function returns an error.
func Load(ctx context.Context, config Config, cat Catalog) (_ io.Closer, err error) {
	closers := make(closerGroup, 0)
	defer func() {
		// If loading fails, clear out the catalog and close down all plugins
		// that have been loaded thus far.
		if err != nil {
			for _, pluginRepo := range cat.Plugins() {
				pluginRepo.Clear()
			}
			for _, serviceRepo := range cat.Services() {
				serviceRepo.Clear()
			}
			closers.Close()
		}
	}()

	pluginRepos, err := makeBindablePluginRepos(cat.Plugins())
	if err != nil {
		return nil, err
	}
	serviceRepos, err := makeBindableServiceRepos(cat.Services())
	if err != nil {
		return nil, err
	}

	pluginCounts := make(map[string]int)

	for _, pluginConfig := range config.PluginConfigs {
		pluginLog := makePluginLog(config.Log, pluginConfig)

		pluginRepo, ok := pluginRepos[pluginConfig.Type]
		if !ok {
			pluginLog.Error("Unsupported plugin type")
			return nil, fmt.Errorf("unsupported plugin type %q", pluginConfig.Type)
		}

		if pluginConfig.Disabled {
			pluginLog.Debug("Not loading plugin; disabled")
			continue
		}

		plugin, err := loadPlugin(ctx, pluginRepo.BuiltIns(), pluginConfig, pluginLog, config.HostServices)
		if err != nil {
			pluginLog.WithError(err).Error("Failed to load plugin")
			return nil, fmt.Errorf("failed to load plugin %q: %w", pluginConfig.Name, err)
		}

		// Add the plugin to the closers even though it has not been completely
		// configured. If anything goes wrong (i.e. failure to configure,
		// panic, etc.) we want the defer above to close the plugin. Failure to
		// do so can orphan external plugin processes.
		closers = append(closers, pluginCloser{plugin: plugin, log: pluginLog})

		configurer, err := plugin.bindRepos(pluginRepo, serviceRepos)
		if err != nil {
			pluginLog.WithError(err).Error("Failed to bind plugin")
			return nil, fmt.Errorf("failed to bind plugin %q: %w", pluginConfig.Name, err)
		}

		switch {
		case configurer != nil:
			if err := configurer.Configure(ctx, config.CoreConfig, pluginConfig.Data); err != nil {
				pluginLog.WithError(err).Error("Failed to configure plugin")
				return nil, fmt.Errorf("failed to configure plugin %q: %w", pluginConfig.Name, err)
			}
		case pluginConfig.Data != "":
			pluginLog.WithField(telemetry.Reason, "no supported configuration interface").Error("Failed to configure plugin")
			return nil, fmt.Errorf("failed to configure plugin %q: no supported configuration interface found", pluginConfig.Name)
		}

		pluginLog.Info("Plugin loaded")
		pluginCounts[pluginConfig.Type]++
	}

	// Make sure all of the plugin constraints are satisfied
	for pluginType, pluginRepo := range pluginRepos {
		if err := pluginRepo.Constraints().Check(pluginCounts[pluginType]); err != nil {
			return nil, fmt.Errorf("plugin type %q constraint not satisfied: %w", pluginType, err)
		}
	}

	return closers, nil
}

func makePluginLog(log logrus.FieldLogger, pluginConfig PluginConfig) logrus.FieldLogger {
	return log.WithFields(logrus.Fields{
		telemetry.PluginName: pluginConfig.Name,
		telemetry.PluginType: pluginConfig.Type,
		telemetry.External:   pluginConfig.IsExternal(),
	})
}

func loadPlugin(ctx context.Context, builtIns []BuiltIn, pluginConfig PluginConfig, pluginLog logrus.FieldLogger, hostServices []pluginsdk.ServiceServer) (*pluginImpl, error) {
	if pluginConfig.IsExternal() {
		return loadExternal(ctx, externalConfig{
			Name:         pluginConfig.Name,
			Type:         pluginConfig.Type,
			Path:         pluginConfig.Path,
			Args:         pluginConfig.Args,
			Checksum:     pluginConfig.Checksum,
			Log:          pluginLog,
			HostServices: hostServices,
		})
	}

	for _, builtIn := range builtIns {
		if pluginConfig.Name == builtIn.Name {
			return loadBuiltIn(ctx, builtIn, BuiltInConfig{
				Log:          pluginLog,
				HostServices: hostServices,
			})
		}
	}
	return nil, fmt.Errorf("no built-in plugin %q for type %q", pluginConfig.Name, pluginConfig.Type)
}

func initPlugin(ctx context.Context, conn grpc.ClientConnInterface, hostServices []pluginsdk.ServiceServer) ([]string, error) {
	var hostServiceGRPCServiceNames []string
	for _, hostService := range hostServices {
		hostServiceGRPCServiceNames = append(hostServiceGRPCServiceNames, hostService.GRPCServiceName())
	}
	return private.Init(ctx, conn, hostServiceGRPCServiceNames)
}

type pluginInfo struct {
	name string
	typ  string
}

func (info pluginInfo) Name() string {
	return info.name
}

func (info pluginInfo) Type() string {
	return info.typ
}

type pluginCloser struct {
	plugin io.Closer
	log    logrus.FieldLogger
}

func (c pluginCloser) Close() error {
	c.log.Debug("Unloading plugin")
	if err := c.plugin.Close(); err != nil {
		c.log.WithError(err).Error("Failed to unload plugin")
		return err
	}
	c.log.Info("Plugin unloaded")
	return nil
}
