// +build ignore

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire-plugin-sdk/private/proto/test"
	"github.com/spiffe/spire/proto/private/test/legacyplugin"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// the ID used to dial host services
	hostServicesID = 1
)

func main() {
	plugin := new(Plugin)

	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Trace,
		Output:     os.Stderr,
		JSONFormat: true,
	})
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: goplugin.HandshakeConfig{
			ProtocolVersion:  1,
			MagicCookieKey:   "SomePlugin",
			MagicCookieValue: "SomePlugin",
		},
		Plugins: map[string]goplugin.Plugin{
			"LEGACY": &hcServerPlugin{
				logger: logger,
				plugin: plugin,
			},
		},
		Logger:     logger,
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}

// HostServiceBroker is used by plugins that implement the NeedsHostBroker
// service to obtain host service clients.
type HostServiceBroker interface {
	GetHostService(HostServiceClient) (has bool, err error)
}

// HostServiceClient is used to initialize a host service client.
type HostServiceClient interface {
	HostServiceType() string

	// InitHostServiceClient initializes the host service client.
	InitHostServiceClient(conn grpc.ClientConnInterface)
}

// NeedsLogger is implemented by plugin/service implementations that need a
// logger that is connected to the SPIRE core logger.
type NeedsLogger interface {
	SetLogger(hclog.Logger)
}

// NeedsHostServices is implemented by plugin/service implementations that need
// to obtain clients to host services.
type NeedsHostServices interface {
	BrokerHostServices(HostServiceBroker) error
}

type Plugin struct {
	legacyplugin.UnimplementedSomePluginServer

	log         hclog.Logger
	hostService someHostServiceClient
}

var _ NeedsLogger = (*Plugin)(nil)
var _ NeedsHostServices = (*Plugin)(nil)

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) BrokerHostServices(broker HostServiceBroker) error {
	if has, err := broker.GetHostService(&p.hostService); err != nil {
		return err
	} else if !has {
		return errors.New("required host service was not available")
	}
	return nil
}

func (p *Plugin) PluginEcho(ctx context.Context, req *legacyplugin.EchoRequest) (*legacyplugin.EchoResponse, error) {
	out := wrap(req.In, "plugin")
	resp, err := p.hostService.HostServiceEcho(ctx, &test.EchoRequest{In: out})
	if err != nil {
		return nil, err
	}
	return &legacyplugin.EchoResponse{Out: resp.Out}, nil
}

func (p *Plugin) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	p.log.Info("CONFIGURED")
	if req.GlobalConfig.TrustDomain != "example.org" {
		return nil, status.Errorf(codes.InvalidArgument, "expected trust domain %q; got %q", "example.org", req.GlobalConfig.TrustDomain)
	}
	if req.Configuration != "GOOD" {
		return nil, status.Error(codes.InvalidArgument, "bad config")
	}
	return &plugin.ConfigureResponse{}, nil
}

type hcServerPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	logger hclog.Logger
	plugin *Plugin
}

var _ goplugin.GRPCPlugin = (*hcServerPlugin)(nil)

func (p *hcServerPlugin) GRPCServer(b *goplugin.GRPCBroker, s *grpc.Server) (err error) {
	legacyplugin.RegisterSomePluginServer(s, p.plugin)
	spi.RegisterPluginInitServer(s, &initServer{
		logger: p.logger,
		dialer: &grpcBrokerDialer{b: b},
		impls:  []interface{}{p.plugin},
	})
	return nil
}

func (p *hcServerPlugin) GRPCClient(ctx context.Context, b *goplugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return nil, errors.New("unimplemented")
}

type grpcBrokerDialer struct {
	b *goplugin.GRPCBroker
}

func (d grpcBrokerDialer) DialHost() (*grpc.ClientConn, error) {
	return d.b.Dial(hostServicesID)
}

type initServer struct {
	spi.UnsafePluginInitServer

	logger hclog.Logger
	dialer *grpcBrokerDialer
	impls  []interface{}
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

	return &spi.InitResponse{}, nil
}

type hostServiceBroker struct {
	dialer       *grpcBrokerDialer
	hostServices map[string]bool
	c            *grpc.ClientConn
	closeOnce    sync.Once
}

func newHostServiceBroker(dialer *grpcBrokerDialer, hostServices []string) *hostServiceBroker {
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
			return false, fmt.Errorf("unable to dial service broker on host: %v", err)
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

type someHostServiceClient struct {
	test.SomeHostServiceClient
}

func (pc *someHostServiceClient) HostServiceType() string { return "SomeHostService" }

func (pc *someHostServiceClient) InitHostServiceClient(conn grpc.ClientConnInterface) {
	pc.SomeHostServiceClient = test.NewSomeHostServiceClient(conn)
}

func wrap(s string, with string) string {
	return fmt.Sprintf("%s(%s)", with, s)
}
