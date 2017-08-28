package nodeattestor

import (
	"github.com/spiffe/sri/pkg/common/plugin"
	"golang.org/x/net/context"
)

type grpcServer struct {
	delegate Interface
}

func (m *grpcServer) FetchAttestationData(ctx context.Context, req *FetchAttestationDataRequest) (*FetchAttestationDataResponse, error) {
	response, err := m.delegate.FetchAttestationData(req)
	return response, err
}

func (m *grpcServer) Configure(ctx context.Context, req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	response, err := m.delegate.Configure(req)
	return response, err
}

func (m *grpcServer) GetPluginInfo(ctx context.Context, req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	response, err := m.delegate.GetPluginInfo(req)
	return response, err
}

type grpcClient struct {
	client NodeAttestorClient
}

func (m *grpcClient) FetchAttestationData(req *FetchAttestationDataRequest) (*FetchAttestationDataResponse, error) {
	res, err := m.client.FetchAttestationData(context.Background(), req)
	return res, err
}

func (m *grpcClient) Configure(req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	res, err := m.client.Configure(context.Background(), req)
	return res, err
}

func (m *grpcClient) GetPluginInfo(req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	res, err := m.client.GetPluginInfo(context.Background(), req)
	return res, err
}
