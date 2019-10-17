package catalog

import (
	"context"
	"sort"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/zeebo/errs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type hostDialer interface {
	DialHost() (*grpc.ClientConn, error)
}

type catalogPluginConfig struct {
	Log           logrus.FieldLogger
	Name          string
	Plugin        PluginClient
	KnownServices []ServiceClient
	HostServices  []HostServiceServer
}

func newCatalogPlugin(ctx context.Context, c *grpc.ClientConn, config catalogPluginConfig) (*CatalogPlugin, error) {
	hostServiceTypes, err := makeHostServiceTypes(config.HostServices)
	if err != nil {
		return nil, err
	}

	servicesMap, err := makeServicesMap(config.KnownServices)
	if err != nil {
		return nil, err
	}

	// Try an initialize the plugin. If this fails due to "unimplemented" then
	// the plugin is an old-style plugin and does not offer services.
	initClient := spi.NewPluginInitClient(c)
	resp, err := initClient.Init(ctx, &spi.InitRequest{
		HostServices: hostServiceTypes,
	})
	if err != nil && status.Code(err) != codes.Unimplemented {
		return nil, errs.Wrap(err)
	}

	var serviceImpls []interface{}
	var serviceNames []string
	if resp != nil {
		for _, typ := range resp.PluginServices {
			service, ok := servicesMap[typ]
			if !ok {
				config.Log.WithField(telemetry.PluginService, typ).Warn("Unknown service type.")
				continue
			}
			serviceImpls = append(serviceImpls, service.NewServiceClient(c))
			serviceNames = append(serviceNames, typ)
		}
		sort.Strings(serviceNames)
	}

	pluginImpl := config.Plugin.NewPluginClient(c)

	return &CatalogPlugin{
		name:         config.Name,
		plugin:       pluginImpl,
		all:          append([]interface{}{pluginImpl}, serviceImpls...),
		serviceNames: serviceNames,
	}, nil
}

func initPluginServer(s *grpc.Server, dialer hostDialer, logger hclog.Logger, plugin PluginServer, services []ServiceServer) {
	var impls []interface{}
	var pluginServices []string
	impls = append(impls, plugin.RegisterPluginServer(s))
	for _, service := range services {
		impls = append(impls, service.RegisterServiceServer(s))
		pluginServices = append(pluginServices, service.ServiceType())
	}
	spi.RegisterPluginInitServer(s, &initServer{
		logger:         logger,
		dialer:         dialer,
		impls:          impls,
		pluginServices: pluginServices,
	})
}

type initServer struct {
	logger         hclog.Logger
	dialer         hostDialer
	impls          []interface{}
	pluginServices []string
}

func (p *initServer) Init(ctx context.Context, req *spi.InitRequest) (resp *spi.InitResponse, err error) {
	// create a new broker and make sure it is torn down if there is an error.
	// otherwise, it needs to stay up open as it maintains the client
	// connection for the brokered services.
	broker := newHostServiceBroker(p.dialer, req.HostServices)
	defer func() {
		if err != nil {
			broker.Close()
		}
	}()

	initted := make(map[interface{}]bool)
	for _, impl := range p.impls {
		// skip initialializing the same implementation twice. the plugin and
		// service interface might be implemented by the same underlying struct.
		if initted[impl] {
			continue
		}
		initted[impl] = true

		// wire up logging
		if x, ok := impl.(NeedsLogger); ok {
			x.SetLogger(p.logger)
		}

		// initialize host service dependencies
		if x, ok := impl.(NeedsHostServices); ok {
			if err := x.BrokerHostServices(broker); err != nil {
				return nil, err
			}
		}
	}

	return &spi.InitResponse{
		PluginServices: p.pluginServices,
	}, nil
}

type hostServiceBroker struct {
	dialer       hostDialer
	hostServices map[string]bool
	c            *grpc.ClientConn
	closeOnce    sync.Once
}

func newHostServiceBroker(dialer hostDialer, hostServices []string) *hostServiceBroker {
	b := &hostServiceBroker{
		dialer:       dialer,
		hostServices: map[string]bool{},
	}
	for _, service := range hostServices {
		b.hostServices[service] = true
	}
	return b
}

func (b *hostServiceBroker) GetHostService(hostService HostServiceClient) (bool, error) {
	if b.c == nil {
		var err error
		b.c, err = b.dialer.DialHost()
		if err != nil {
			return false, errs.New("unable to dial service broker on host: %v", err)
		}
	}
	if !b.hostServices[hostService.HostServiceType()] {
		return false, nil
	}
	hostService.InitHostServiceClient(b.c)
	return true, nil
}

func (b *hostServiceBroker) Close() {
	b.closeOnce.Do(func() {
		if b.c != nil {
			b.c.Close()
		}
	})
}
