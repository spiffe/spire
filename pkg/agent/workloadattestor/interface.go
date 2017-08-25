package workloadattestor

import (
	"net/rpc"

	"google.golang.org/grpc"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/sri/pkg/common/plugin"
)

//Handshake is a common handshake that is shared by the plugin and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "WorkloadAttestor",
	MagicCookieValue: "WorkloadAttestor",
}

type WorkloadAttestor interface {
	Attest(*AttestRequest) (*AttestResponse, error)
	Configure(*sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error)
	GetPluginInfo(*sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error)
}

type WorkloadAttestorPlugin struct {
	WorkloadAttestorImpl WorkloadAttestor
}

func (p WorkloadAttestorPlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p WorkloadAttestorPlugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p WorkloadAttestorPlugin) GRPCServer(s *grpc.Server) error {
	RegisterWorkloadAttestorServer(s, &GRPCServer{WorkloadAttestorImpl: p.WorkloadAttestorImpl})
	return nil
}

func (p WorkloadAttestorPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewWorkloadAttestorClient(c)}, nil
}
