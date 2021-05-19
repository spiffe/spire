package catalog

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/private"
	"github.com/spiffe/spire/pkg/common/telemetry"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	// The Load funcion will ensure that these constraints are satisfied before
	// returning successfully.
	Constraints() Constraints

	// LegacyVersion is called when the catalog detects a legacy plugin to
	// obtain the legacy plugin version. If no legacy version exists for this
	// plugin, this function returns false, which causes the Load() function to
	// fail.
	LegacyVersion() (Version, bool)

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
	Binder() interface{}

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

type HostServiceServer struct {
	// ServiceServer is the service server for the host service.
	ServiceServer pluginsdk.ServiceServer

	// LegacyType is the legacy type for the host service used to initialize
	// legacy plugins. This is optional for new host services that did not
	// existing before the plugin SDK was introduced.
	LegacyType string
}

type Config struct {
	// Log is the logger. It is used for general purpose logging and also
	// provided to the plugins.
	Log logrus.FieldLogger

	// PluginConfigs is the list of plugin configurations.
	PluginConfigs []PluginConfig

	// HostServices are the servers for host services provided by SPIRE to
	// plugins.
	HostServices []HostServiceServer

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
		closers = append(closers, plugin)

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

func loadPlugin(ctx context.Context, builtIns []BuiltIn, pluginConfig PluginConfig, pluginLog logrus.FieldLogger, hostServices []HostServiceServer) (*pluginImpl, error) {
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

	// Extract out the host service servers to supply to the built-in. The
	// legacy type is not needed for built-ins since they cannot be legacy
	// plugins.
	// TODO: no need to do this once legacy plugins are no longer supported
	hostServiceServers := make([]pluginsdk.ServiceServer, 0, len(hostServices))
	for _, hostService := range hostServices {
		hostServiceServers = append(hostServiceServers, hostService.ServiceServer)
	}
	for _, builtIn := range builtIns {
		if pluginConfig.Name == builtIn.Name {
			return loadBuiltIn(ctx, builtIn, BuiltInConfig{
				Log:          pluginLog,
				HostServices: hostServiceServers,
			})
		}
	}
	return nil, fmt.Errorf("no built-in plugin %q for type %q", pluginConfig.Name, pluginConfig.Type)
}

func initPlugin(ctx context.Context, conn grpc.ClientConnInterface, hostServices []HostServiceServer) ([]string, error) {
	grpcServiceNames, err := private.Init(ctx, conn, hostServiceGRPCServiceNames(hostServices))
	switch status.Code(err) {
	case codes.OK:
		return grpcServiceNames, nil
	case codes.Unimplemented:
		return nil, initLegacyPlugin(ctx, conn, legacyHostServiceTypes(hostServices))
	default:
		return nil, err
	}
}

func initLegacyPlugin(ctx context.Context, conn grpc.ClientConnInterface, hostServiceTypes []string) error {
	// This is a legacy plugin. Initialize with the old interface but don't
	// bother trying to obtain service names since no services were defined
	// during the lifetime of the legacy plugin system.
	var legacyClient spi.PluginInitPluginClient
	legacyClient.InitClient(conn)
	_, err := legacyClient.Init(ctx, &spi.InitRequest{
		HostServices: hostServiceTypes,
	})
	return err
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

func legacyHostServiceTypes(servers []HostServiceServer) []string {
	var out []string
	for _, server := range servers {
		if server.LegacyType != "" {
			out = append(out, server.LegacyType)
		}
	}
	return out
}

func hostServiceGRPCServiceNames(servers []HostServiceServer) []string {
	var grpcServiceNames []string
	for _, server := range servers {
		grpcServiceNames = append(grpcServiceNames, server.ServiceServer.GRPCServiceName())
	}
	sort.Strings(grpcServiceNames)
	return grpcServiceNames
}
