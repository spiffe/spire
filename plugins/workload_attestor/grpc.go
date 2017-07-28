package workloadattestor

import (
	"github.com/spiffe/node-agent/plugins/workload_attestor/proto"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	WorkloadAttestorImpl WorkloadAttestor
}

func (m *GRPCServer) Attest(ctx context.Context, req *proto.AttestRequest) (*proto.AttestResponse, error) {
	response, err := m.WorkloadAttestorImpl.Attest(req.Pid)
	return &proto.AttestResponse{Selectors: response}, err
}

func (m *GRPCServer) Configure(ctx context.Context, req *proto.ConfigureRequest) (*proto.Empty, error) {
	err := m.WorkloadAttestorImpl.Configure(req.Configuration)
	return &proto.Empty{}, err
}

type GRPCClient struct {
	client proto.WorkloadAttestorClient
}

func (m *GRPCClient) Attest(pid int32) ([]string, error) {
	res, err := m.client.Attest(context.Background(), &proto.AttestRequest{pid})
	if err != nil {
		return []string{}, err
	}
	return res.Selectors, err
}

func (m *GRPCClient) Configure(configuration string) error {
	_, err := m.client.Configure(context.Background(), &proto.ConfigureRequest{
		Configuration: configuration,
	})
	return err
}
