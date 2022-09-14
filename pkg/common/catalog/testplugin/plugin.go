package testplugin

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/private/proto/test"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Plugin struct {
	test.UnimplementedSomePluginServer
	test.UnimplementedSomeServiceServer
	configv1.UnimplementedConfigServer

	log         hclog.Logger
	hostService test.SomeHostServiceServiceClient
}

var _ pluginsdk.NeedsLogger = (*Plugin)(nil)
var _ pluginsdk.NeedsHostServices = (*Plugin)(nil)

func BuiltIn(registerConfig bool) catalog.BuiltIn {
	plugin := new(Plugin)
	serviceServers := []pluginsdk.ServiceServer{test.SomeServiceServiceServer(plugin)}
	if registerConfig {
		serviceServers = append(serviceServers, configv1.ConfigServiceServer(plugin))
	}
	return catalog.MakeBuiltIn("test", test.SomePluginPluginServer(plugin), serviceServers...)
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) BrokerHostServices(broker pluginsdk.ServiceBroker) error {
	if !broker.BrokerClient(&p.hostService) {
		return errors.New("host service was not available on broker")
	}
	return nil
}

func (p *Plugin) PluginEcho(ctx context.Context, req *test.EchoRequest) (*test.EchoResponse, error) {
	out := wrap(req.In, "plugin")
	resp, err := p.hostService.HostServiceEcho(ctx, &test.EchoRequest{In: out})
	if err != nil {
		return nil, err
	}
	return &test.EchoResponse{Out: resp.Out}, nil
}

func (p *Plugin) ServiceEcho(ctx context.Context, req *test.EchoRequest) (*test.EchoResponse, error) {
	out := wrap(req.In, "service")
	resp, err := p.hostService.HostServiceEcho(ctx, &test.EchoRequest{In: out})
	if err != nil {
		return nil, err
	}
	return &test.EchoResponse{Out: resp.Out}, nil
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	p.log.Info("CONFIGURED")
	if req.CoreConfiguration.TrustDomain != "example.org" {
		return nil, status.Errorf(codes.InvalidArgument, "expected trust domain %q; got %q", "example.org", req.CoreConfiguration.TrustDomain)
	}
	if req.HclConfiguration != "GOOD" {
		return nil, status.Error(codes.InvalidArgument, "bad config")
	}
	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Close() error {
	p.log.Info("CLOSED")
	return nil
}

type SomeHostService struct {
	test.UnimplementedSomeHostServiceServer
}

func (SomeHostService) HostServiceEcho(ctx context.Context, req *test.EchoRequest) (*test.EchoResponse, error) {
	pluginName, ok := catalog.PluginNameFromHostServiceContext(ctx)
	if !ok {
		return nil, status.Error(codes.Internal, "plugin name not available on host service context")
	}
	return &test.EchoResponse{Out: wrap(wrap(req.In, pluginName), "hostService")}, nil
}

func wrap(s string, with string) string {
	return fmt.Sprintf("%s(%s)", with, s)
}
