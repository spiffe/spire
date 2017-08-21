package controlplaneca

import (
	"github.com/spiffe/sri/common/plugin"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	ControlPlaneCaImpl ControlPlaneCa
}

func (m *GRPCServer) Configure(ctx context.Context, req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	response, err := m.ControlPlaneCaImpl.Configure(req.Configuration)
	return &sriplugin.ConfigureResponse{ErrorList: response}, err
}

func (m *GRPCServer) GetPluginInfo(ctx context.Context, req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	response, err := m.ControlPlaneCaImpl.GetPluginInfo()
	return response, err
}

func (m *GRPCServer) SignCsr(ctx context.Context, req *SignCsrRequest) (*SignCsrResponse, error) {
	response, err := m.ControlPlaneCaImpl.SignCsr(req.Csr)
	return &SignCsrResponse{SignedCertificate: response}, err
}

func (m *GRPCServer) GenerateCsr(ctx context.Context, req *GenerateCsrRequest) (*GenerateCsrResponse, error) {
	response, err := m.ControlPlaneCaImpl.GenerateCsr()
	return &GenerateCsrResponse{Csr: response}, err
}

func (m *GRPCServer) FetchCertificate(ctx context.Context, req *FetchCertificateRequest) (*FetchCertificateResponse, error) {
	response, err := m.ControlPlaneCaImpl.FetchCertificate()
	return &FetchCertificateResponse{StoredIntermediateCert: response}, err
}

func (m *GRPCServer) LoadCertificate(ctx context.Context, req *LoadCertificateRequest) (*LoadCertificateResponse, error) {
	err := m.ControlPlaneCaImpl.LoadCertificate(req.SignedIntermediateCert)
	return &LoadCertificateResponse{}, err
}

type GRPCClient struct {
	client ControlPlaneCAClient
}

func (m *GRPCClient) Configure(configuration string) ([]string, error) {
	response, err := m.client.Configure(context.Background(), &sriplugin.ConfigureRequest{configuration})
	if err != nil {
		return []string{}, err
	}
	return response.ErrorList, err
}

func (m *GRPCClient) GetPluginInfo() (*sriplugin.GetPluginInfoResponse, error) {
	response, err := m.client.GetPluginInfo(context.Background(), &sriplugin.GetPluginInfoRequest{})
	return response, err
}

func (m *GRPCClient) SignCsr(csr []byte) (signedCertificate []byte, err error) {
	response, err := m.client.SignCsr(context.Background(), &SignCsrRequest{Csr: csr})
	return response.SignedCertificate, err
}

func (m *GRPCClient) GenerateCsr() (csr []byte, err error) {
	response, err := m.client.GenerateCsr(context.Background(), &GenerateCsrRequest{})
	return response.Csr, err
}

func (m *GRPCClient) FetchCertificate() (storedIntermediateCert []byte, err error) {
	response, err := m.client.FetchCertificate(context.Background(), &FetchCertificateRequest{})
	return response.StoredIntermediateCert, err
}

func (m *GRPCClient) LoadCertificate(signedIntermediateCert []byte) error {
	_, err := m.client.LoadCertificate(context.Background(), &LoadCertificateRequest{SignedIntermediateCert: signedIntermediateCert})
	return err
}
