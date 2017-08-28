package ca

import (
	"github.com/spiffe/sri/pkg/common/plugin"
	"golang.org/x/net/context"
)

type grpcServer struct {
	delegate Interface
}

func (m *grpcServer) Configure(ctx context.Context, req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	response, err := m.delegate.Configure(req.Configuration)
	return &sriplugin.ConfigureResponse{ErrorList: response}, err
}

func (m *grpcServer) GetPluginInfo(ctx context.Context, req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	response, err := m.delegate.GetPluginInfo()
	return response, err
}

func (m *grpcServer) SignCsr(ctx context.Context, req *SignCsrRequest) (*SignCsrResponse, error) {
	response, err := m.delegate.SignCsr(req.Csr)
	return &SignCsrResponse{SignedCertificate: response}, err
}

func (m *grpcServer) GenerateCsr(ctx context.Context, req *GenerateCsrRequest) (*GenerateCsrResponse, error) {
	response, err := m.delegate.GenerateCsr()
	return &GenerateCsrResponse{Csr: response}, err
}

func (m *grpcServer) FetchCertificate(ctx context.Context, req *FetchCertificateRequest) (*FetchCertificateResponse, error) {
	response, err := m.delegate.FetchCertificate()
	return &FetchCertificateResponse{StoredIntermediateCert: response}, err
}

func (m *grpcServer) LoadCertificate(ctx context.Context, req *LoadCertificateRequest) (*LoadCertificateResponse, error) {
	err := m.delegate.LoadCertificate(req.SignedIntermediateCert)
	return &LoadCertificateResponse{}, err
}

type grpcClient struct {
	client ControlPlaneCAClient
}

func (m *grpcClient) Configure(configuration string) ([]string, error) {
	response, err := m.client.Configure(context.Background(), &sriplugin.ConfigureRequest{configuration})
	if err != nil {
		return []string{}, err
	}
	return response.ErrorList, err
}

func (m *grpcClient) GetPluginInfo() (*sriplugin.GetPluginInfoResponse, error) {
	response, err := m.client.GetPluginInfo(context.Background(), &sriplugin.GetPluginInfoRequest{})
	return response, err
}

func (m *grpcClient) SignCsr(csr []byte) (signedCertificate []byte, err error) {
	response, err := m.client.SignCsr(context.Background(), &SignCsrRequest{Csr: csr})
	return response.SignedCertificate, err
}

func (m *grpcClient) GenerateCsr() (csr []byte, err error) {
	response, err := m.client.GenerateCsr(context.Background(), &GenerateCsrRequest{})
	return response.Csr, err
}

func (m *grpcClient) FetchCertificate() (storedIntermediateCert []byte, err error) {
	response, err := m.client.FetchCertificate(context.Background(), &FetchCertificateRequest{})
	return response.StoredIntermediateCert, err
}

func (m *grpcClient) LoadCertificate(signedIntermediateCert []byte) error {
	_, err := m.client.LoadCertificate(context.Background(), &LoadCertificateRequest{SignedIntermediateCert: signedIntermediateCert})
	return err
}
