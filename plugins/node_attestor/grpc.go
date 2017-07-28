package nodeattestor

import (
	"github.com/spiffe/control-plane/plugins/node_attestor/proto"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	NodeAttestorImpl NodeAttestor
}

func (m *GRPCServer) Attest(ctx context.Context, req *proto.AttestedData) (*proto.AttestResponse, error) {
	response, err := m.NodeAttestorImpl.Attest(req)
	return response, err
}

type GRPCClient struct {
	client proto.NodeAttestorClient
}

func (m *GRPCClient) Attest(attestedData *proto.AttestedData) (*proto.AttestResponse, error) {
	response, err := m.client.Attest(context.Background(), attestedData)
	return response, err
}
