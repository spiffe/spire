package catalog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"google.golang.org/grpc"
)

// Plugin is a loaded plugin.
type Plugin interface {
	// Closer is used to unload the plugin. Any facades initialized by the
	// call to bind are considered invalidated after the plugin is closed.
	io.Closer

	// Bind binds the given facades to the plugin. It also returns a Configurer
	// that can be used to configure the plugin. If the plugin does not support
	// a given facade, an error will be returned. This function is designed
	// only for use by unit-tests for built-in plugin implementations or fake
	// facade implementations that rely on built-ins.
	Bind(facades ...Facade) (Configurer, error)
}

type pluginImpl struct {
	closerGroup

	conn             grpc.ClientConnInterface
	info             PluginInfo
	log              logrus.FieldLogger
	grpcServiceNames []string
}

func newPlugin(ctx context.Context, conn grpc.ClientConnInterface, info PluginInfo, log logrus.FieldLogger, closers closerGroup, hostServices []HostServiceServer) (*pluginImpl, error) {
	grpcServiceNames, err := initPlugin(ctx, conn, hostServices)
	if err != nil {
		return nil, err
	}

	return &pluginImpl{
		conn:             conn,
		info:             info,
		log:              log,
		closerGroup:      closers,
		grpcServiceNames: grpcServiceNames,
	}, nil
}

// Bind implements the Plugin interface method of the same name.
func (p *pluginImpl) Bind(facades ...Facade) (Configurer, error) {
	if p.isLegacy() {
		return nil, errors.New("cannot bind to a legacy plugin")
	}

	grpcServiceNames := grpcServiceNameSet(p.grpcServiceNames)

	var impl interface{}
	for _, facade := range facades {
		if _, ok := grpcServiceNames[facade.GRPCServiceName()]; !ok {
			return nil, fmt.Errorf("plugin does not support facade service %q", facade.GRPCServiceName())
		}
		if facadeImpl := p.initFacade(facade); impl == nil {
			// Grab the first impl.
			// TODO: This will not be necessary when all built-ins transition
			// to the v1 interfaces.
			impl = facadeImpl
		}
	}

	configurer, err := p.makeConfigurer(impl, grpcServiceNames)
	if err != nil {
		return nil, err
	}
	if configurer == nil {
		configurer = configurerUnsupported{}
	}
	return configurer, nil
}

func (p *pluginImpl) isLegacy() bool {
	return len(p.grpcServiceNames) == 0
}

func (p *pluginImpl) bindFacade(repo bindable, facade Facade) interface{} {
	impl := p.initFacade(facade)
	repo.bind(facade)
	return impl
}

func (p *pluginImpl) initFacade(facade Facade) interface{} {
	facade.InitInfo(p.info)
	facade.InitLog(p.log)
	return facade.InitClient(p.conn)
}

func (p *pluginImpl) bindRepos(pluginRepo bindablePluginRepo, serviceRepos []bindableServiceRepo) (Configurer, error) {
	grpcServiceNames := grpcServiceNameSet(p.grpcServiceNames)

	var impl interface{}
	if p.isLegacy() {
		if legacyVersion, ok := pluginRepo.LegacyVersion(); ok {
			p.log.Warn("Legacy plugins are deprecated and will be unsupported in a future release. Please migrate the plugin to use the Plugin SDK.")
			impl = p.bindFacade(pluginRepo, legacyVersion.New())
		} else {
			return nil, fmt.Errorf("no legacy version available for plugin type %q", p.info.Type())
		}
	} else {
		impl = p.bindRepo(pluginRepo, grpcServiceNames)
		for _, serviceRepo := range serviceRepos {
			p.bindRepo(serviceRepo, grpcServiceNames)
		}
	}

	configurer, err := p.makeConfigurer(impl, grpcServiceNames)
	if err != nil {
		return nil, err
	}

	switch {
	case impl == nil:
		return nil, fmt.Errorf("no supported plugin interface found in: %q", p.grpcServiceNames)
	case len(grpcServiceNames) > 0:
		for _, grpcServiceName := range sortStringSet(grpcServiceNames) {
			p.log.WithField(telemetry.PluginService, grpcServiceName).Warn("Unsupported plugin service found")
		}
	}

	return configurer, nil
}

func (p *pluginImpl) makeConfigurer(impl interface{}, grpcServiceNames map[string]struct{}) (Configurer, error) {
	repo := new(configurerRepo)
	bindable, err := makeBindableServiceRepo(repo)
	if err != nil {
		return nil, err
	}
	p.bindRepo(bindable, grpcServiceNames)
	if repo.configurer != nil {
		return repo.configurer, nil
	}
	if client, ok := impl.(legacyConfigureClient); ok {
		// TODO: this hack should nominally only happen for legacy plugins only
		// but we're in an awkward transition stage where built-ins are
		// "non-legacy" but implementing the v0 interfaces.
		return configurerLegacy{client: client}, nil
	}
	return nil, nil
}

func (p *pluginImpl) bindRepo(repo bindableServiceRepo, grpcServiceNames map[string]struct{}) interface{} {
	versions := repo.Versions()

	var impl interface{}
	for _, version := range versions {
		facade := version.New()
		if _, ok := grpcServiceNames[facade.GRPCServiceName()]; ok {
			delete(grpcServiceNames, facade.GRPCServiceName())
			// Use the first matching version (in case the plugin implements
			// more than one). The rest will be removed from the list of
			// service names above so we can properly warn of unhandled
			// services without false negatives.
			if impl != nil {
				continue
			}
			warnIfDeprecated(p.log, version, versions[0])
			impl = p.bindFacade(repo, facade)
		}
	}
	return impl
}

func warnIfDeprecated(log logrus.FieldLogger, thisVersion, latestVersion Version) {
	if thisVersion.Deprecated() {
		log = log.WithField(telemetry.DeprecatedServiceName, thisVersion.New().GRPCServiceName())
		if !latestVersion.Deprecated() {
			log.WithField(telemetry.PreferredServiceName, latestVersion.New().GRPCServiceName())
		}
		log.Warn("Service is deprecated and will be removed in a future release")
	}
}

func grpcServiceNameSet(grpcServiceNames []string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, grpcServiceName := range grpcServiceNames {
		set[grpcServiceName] = struct{}{}
	}
	return set
}

func sortStringSet(set map[string]struct{}) []string {
	ss := make([]string, 0, len(set))
	for s := range set {
		ss = append(ss, s)
	}
	sort.Strings(ss)
	return ss
}
