package controlplaneca

import (
	common "github.com/spiffe/sri/control_plane/plugins/common/proto"
	"github.com/spiffe/sri/control_plane/plugins/control_plane_ca/proto"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	ControlPlaneCaImpl ControlPlaneCa
}

func (m *GRPCServer) Configure(ctx context.Context, req *common.ConfigureRequest) (*common.ConfigureResponse, error) {
	response, err := m.ControlPlaneCaImpl.Configure(req.Configuration)
	return &common.ConfigureResponse{ErrorList: response}, err
}

func (m *GRPCServer) GetPluginInfo(ctx context.Context, req *common.GetPluginInfoRequest) (*common.GetPluginInfoResponse, error) {
	response, err := m.ControlPlaneCaImpl.GetPluginInfo()
	return response, err
}

func (m *GRPCServer) SignCsr(ctx context.Context, req *sri_proto.SignCsrRequest) (*sri_proto.SignCsrResponse, error) {
	response, err := m.ControlPlaneCaImpl.SignCsr(req.Csr)
	return &sri_proto.SignCsrResponse{SignedCertificate: response}, err
}

func (m *GRPCServer) GenerateCsr(ctx context.Context, req *sri_proto.GenerateCsrRequest) (*sri_proto.GenerateCsrResponse, error) {
	response, err := m.ControlPlaneCaImpl.GenerateCsr()
	return &sri_proto.GenerateCsrResponse{Csr: response}, err
}

func (m *GRPCServer) FetchCertificate(ctx context.Context, req *sri_proto.FetchCertificateRequest) (*sri_proto.FetchCertificateResponse, error) {
	response, err := m.ControlPlaneCaImpl.FetchCertificate()
	return &sri_proto.FetchCertificateResponse{StoredIntermediateCert: response}, err
}

func (m *GRPCServer) LoadCertificate(ctx context.Context, req *sri_proto.LoadCertificateRequest) (*sri_proto.LoadCertificateResponse, error) {
	err := m.ControlPlaneCaImpl.LoadCertificate(req.SignedIntermediateCert)
	return &sri_proto.LoadCertificateResponse{}, err
}

type GRPCClient struct {
	client sri_proto.ControlPlaneCAClient
}

func (m *GRPCClient) Configure(configuration string) ([]string, error) {
	response, err := m.client.Configure(context.Background(), &common.ConfigureRequest{configuration})
	if err != nil {
		return []string{}, err
	}
	return response.ErrorList, err
}

func (m *GRPCClient) GetPluginInfo() (*common.GetPluginInfoResponse, error) {
	response, err := m.client.GetPluginInfo(context.Background(), &common.GetPluginInfoRequest{})
	return response, err
}

func (m *GRPCClient) SignCsr(csr []byte) (signedCertificate []byte, err error) {
	response, err := m.client.SignCsr(context.Background(), &sri_proto.SignCsrRequest{Csr: csr})
	return response.SignedCertificate, err
}

func (m *GRPCClient) GenerateCsr() (csr []byte, err error) {
	response, err := m.client.GenerateCsr(context.Background(), &sri_proto.GenerateCsrRequest{})
	return response.Csr, err
}

func (m *GRPCClient) FetchCertificate() (storedIntermediateCert []byte, err error) {
	response, err := m.client.FetchCertificate(context.Background(), &sri_proto.FetchCertificateRequest{})
	return response.StoredIntermediateCert, err
}

func (m *GRPCClient) LoadCertificate(signedIntermediateCert []byte) error {
	_, err := m.client.LoadCertificate(context.Background(), &sri_proto.LoadCertificateRequest{SignedIntermediateCert: signedIntermediateCert})
	return err
}
