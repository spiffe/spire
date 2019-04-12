package test

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/common/catalog/internal"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func NewTestPlugin() TestPluginPlugin {
	return &testPlugin{}
}

type testPlugin struct {
	log hclog.Logger
	hs  TestHostServiceClient
}

func (s *testPlugin) SetLogger(log hclog.Logger) {
	s.log = log.ResetNamed("pluginimpl")
}

func (s *testPlugin) BrokerHostServices(broker internal.HostServiceBroker) error {
	has, err := broker.GetHostService(TestHostServiceHostServiceClient(&s.hs))
	if err != nil {
		return err
	}
	if !has && s.log != nil {
		// s.log will only be nil if this is not used within the new plugin framework (i.e. old plugin test)
		s.log.Warn("Host service not available.", "hostservice", "TestHostService")
	}
	return nil
}

func (s *testPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	var trustDomain string
	if req.GlobalConfig != nil {
		trustDomain = req.GlobalConfig.TrustDomain
	}
	if s.log != nil {
		// s.log will only be nil if this is not used within the new plugin framework (i.e. old plugin test)
		s.log.Info("Configure called.", "trustdomain", trustDomain, "config", req.Configuration)
	}
	if req.Configuration == "BAD" {
		return nil, status.Error(codes.InvalidArgument, "BAD configuration")
	}
	return &spi.ConfigureResponse{}, nil
}

func (s *testPlugin) CallPlugin(ctx context.Context, req *Request) (*Response, error) {
	out := req.In
	if s.hs != nil {
		resp, err := s.hs.CallHostService(ctx, &Request{
			In: req.In,
		})
		if err != nil {
			return nil, err
		}
		out = resp.Out
	}
	return &Response{
		Out: fmt.Sprintf("plugin(%s)", out),
	}, nil
}
