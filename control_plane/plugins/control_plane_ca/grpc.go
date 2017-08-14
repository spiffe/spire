package controlplaneca

import (
	common "github.com/spiffe/control-plane/plugins/common/proto"
	"github.com/spiffe/control-plane/plugins/control_plane_ca/proto"
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

func (m *GRPCServer) SignCsr(ctx context.Context, req *proto.SignCsrRequest) (*proto.SignCsrResponse, error) {
	response, err := m.ControlPlaneCaImpl.SignCsr(req.Csr)
	return &proto.SignCsrResponse{SignedCertificate: response}, err
}

func (m *GRPCServer) GenerateCsr(ctx context.Context, req *proto.GenerateCsrRequest) (*proto.GenerateCsrResponse, error) {
	response, err := m.ControlPlaneCaImpl.GenerateCsr()
	return &proto.GenerateCsrResponse{Csr: response}, err
}

func (m *GRPCServer) FetchCertificate(ctx context.Context, req *proto.FetchCertificateRequest) (*proto.FetchCertificateResponse, error) {
	response, err := m.ControlPlaneCaImpl.FetchCertificate()
	return &proto.FetchCertificateResponse{StoredIntermediateCert: response}, err
}

func (m *GRPCServer) LoadCertificate(ctx context.Context, req *proto.LoadCertificateRequest) (*proto.LoadCertificateResponse, error) {
	err := m.ControlPlaneCaImpl.LoadCertificate(req.SignedIntermediateCert)
	return &proto.LoadCertificateResponse{}, err
}

type GRPCClient struct {
	client proto.ControlPlaneCAClient
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
	response, err := m.client.SignCsr(context.Background(), &proto.SignCsrRequest{Csr: csr})
	return response.SignedCertificate, err
}

func (m *GRPCClient) GenerateCsr() (csr []byte, err error) {
	response, err := m.client.GenerateCsr(context.Background(), &proto.GenerateCsrRequest{})
	return response.Csr, err
}

func (m *GRPCClient) FetchCertificate() (storedIntermediateCert []byte, err error) {
	response, err := m.client.FetchCertificate(context.Background(), &proto.FetchCertificateRequest{})
	return response.StoredIntermediateCert, err
}

func (m *GRPCClient) LoadCertificate(signedIntermediateCert []byte) error {
	_, err := m.client.LoadCertificate(context.Background(), &proto.LoadCertificateRequest{SignedIntermediateCert: signedIntermediateCert})
	return err
}
