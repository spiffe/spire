package ca

import (
	"github.com/spiffe/sri/pkg/common/plugin"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	ControlPlaneCaImpl ControlPlaneCa
}

func (m *GRPCServer) Configure(ctx context.Context, req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	return m.ControlPlaneCaImpl.Configure(req)
}

func (m *GRPCServer) GetPluginInfo(ctx context.Context, req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	return m.ControlPlaneCaImpl.GetPluginInfo(req)
}

func (m *GRPCServer) SignCsr(ctx context.Context, req *SignCsrRequest) (*SignCsrResponse, error) {
	return m.ControlPlaneCaImpl.SignCsr(req)
}

func (m *GRPCServer) GenerateCsr(ctx context.Context, req *GenerateCsrRequest) (*GenerateCsrResponse, error) {
	return m.ControlPlaneCaImpl.GenerateCsr(req)
}

func (m *GRPCServer) FetchCertificate(ctx context.Context, req *FetchCertificateRequest) (*FetchCertificateResponse, error) {
	return m.ControlPlaneCaImpl.FetchCertificate(req)
}

func (m *GRPCServer) LoadCertificate(ctx context.Context, req *LoadCertificateRequest) (*LoadCertificateResponse, error) {
	return m.ControlPlaneCaImpl.LoadCertificate(req)
}

type GRPCClient struct {
	client ControlPlaneCAClient
}

func (m *GRPCClient) Configure(req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	return m.client.Configure(context.Background(), req)
}
func (m *GRPCClient) GetPluginInfo(req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	return m.client.GetPluginInfo(context.Background(), req)
}

func (m *GRPCClient) SignCsr(request *SignCsrRequest) (response *SignCsrResponse, err error) {
	return m.client.SignCsr(context.Background(), request)
}

func (m *GRPCClient) GenerateCsr(req *GenerateCsrRequest) (*GenerateCsrResponse, error) {
	return m.client.GenerateCsr(context.Background(), req)
}

func (m *GRPCClient) FetchCertificate(req *FetchCertificateRequest) (*FetchCertificateResponse, error) {
	return m.client.FetchCertificate(context.Background(), req)
}

func (m *GRPCClient) LoadCertificate(request *LoadCertificateRequest) (*LoadCertificateResponse, error) {
	response, err := m.client.LoadCertificate(context.Background(), request)
	return response, err
}
