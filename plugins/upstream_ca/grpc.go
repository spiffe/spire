package upstreamca

import (
	"github.com/spiffe/control-plane/plugins/upstream_ca/proto"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	UpstreamCaImpl UpstreamCa
}

func (m *GRPCServer) SubmitCSR(ctx context.Context, req *proto.SubmitCSRRequest) (*proto.SubmitCSRResponse, error) {
	response, err := m.UpstreamCaImpl.SubmitCSR(req.Csr)
	return response, err
}

type GRPCClient struct {
	client proto.NodeClient
}

func (m *GRPCClient) SubmitCSR(csr []byte) (*proto.SubmitCSRResponse, error) {
	response, err := m.client.SubmitCSR(context.Background(), &proto.SubmitCSRRequest{Csr: csr})
	return response, err
}
