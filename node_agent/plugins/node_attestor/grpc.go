package nodeattestor

import (
	"github.com/spiffe/sri/common/plugin"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	NodeAttestorImpl NodeAttestor
}

func (m *GRPCServer) FetchAttestationData(ctx context.Context, req *FetchAttestationDataRequest) (*FetchAttestationDataResponse, error) {
	response, err := m.NodeAttestorImpl.FetchAttestationData(req)
	return response, err
}

func (m *GRPCServer) Configure(ctx context.Context, req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	response, err := m.NodeAttestorImpl.Configure(req)
	return response, err
}

func (m *GRPCServer) GetPluginInfo(ctx context.Context, req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	response, err := m.NodeAttestorImpl.GetPluginInfo(req)
	return response, err
}

type GRPCClient struct {
	client NodeAttestorClient
}

func (m *GRPCClient) FetchAttestationData(req *FetchAttestationDataRequest) (*FetchAttestationDataResponse, error) {
	res, err := m.client.FetchAttestationData(context.Background(), req)
	return res, err
}

func (m *GRPCClient) Configure(req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	res, err := m.client.Configure(context.Background(), req)
	return res, err
}

func (m *GRPCClient) GetPluginInfo(req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	res, err := m.client.GetPluginInfo(context.Background(), req)
	return res, err
}
