package upstreamca

import (
	"github.com/spiffe/spire/pkg/common/plugin"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	UpstreamCaImpl UpstreamCa
}

func (m *GRPCServer) Configure(ctx context.Context, req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	return m.UpstreamCaImpl.Configure(req)
}

func (m *GRPCServer) GetPluginInfo(ctx context.Context, req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	return m.UpstreamCaImpl.GetPluginInfo(req)
}

func (m *GRPCServer) SubmitCSR(ctx context.Context, req *SubmitCSRRequest) (*SubmitCSRResponse, error) {
	return m.UpstreamCaImpl.SubmitCSR(req)
}

type GRPCClient struct {
	client UpstreamCAClient
}

func (m *GRPCClient) Configure(req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	return m.client.Configure(context.Background(), req)
}

func (m *GRPCClient) GetPluginInfo(req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	return m.client.GetPluginInfo(context.Background(), req)
}

func (m *GRPCClient) SubmitCSR(req *SubmitCSRRequest) (*SubmitCSRResponse, error) {
	return m.client.SubmitCSR(context.Background(), req)
}
