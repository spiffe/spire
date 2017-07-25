package nodeattestor

import (
	"github.com/spiffe/node-agent/plugins/node_attestor/proto"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	NodeAttestorImpl NodeAttestor
}

func (m *GRPCServer) FetchAttestationData(ctx context.Context, req *proto.FetchAttestationDataRequest) (*proto.FetchAttestationDataResponse, error) {
	attestationData, err := m.NodeAttestorImpl.FetchAttestationData()
	return &proto.FetchAttestationDataResponse{AttestationData: attestationData}, err
}

func (m *GRPCServer) Configure(ctx context.Context, req *proto.ConfigureRequest) (*proto.Empty, error) {
	err := m.NodeAttestorImpl.Configure(req.Configuration)
	return &proto.Empty{}, err
}

type GRPCClient struct {
	client proto.NodeAttestorClient
}

func (m *GRPCClient) FetchAttestationData() ([]byte, error) {
	res, err := m.client.FetchAttestationData(context.Background(), &proto.FetchAttestationDataRequest{})
	if err != nil {
		return []byte{}, err
	}
	return res.AttestationData, err
}

func (m *GRPCClient) Configure(configuration string) error {
	_, err := m.client.Configure(context.Background(), &proto.ConfigureRequest{
		Configuration: configuration,
	})
	return err
}
