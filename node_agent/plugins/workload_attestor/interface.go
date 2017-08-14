package workloadattestor

import (
	"net/rpc"

	"google.golang.org/grpc"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/sri/node_agent/plugins/common/proto"
	"github.com/spiffe/sri/node_agent/plugins/workload_attestor/proto"
)

//Handshake is a common handshake that is shared by the plugin and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "WorkloadAttestor",
	MagicCookieValue: "WorkloadAttestor",
}


type WorkloadAttestor interface {
	Attest(*node_agent_proto.AttestRequest) (*node_agent_proto.AttestResponse, error)
	Configure(*common.ConfigureRequest) (*common.ConfigureResponse, error)
	GetPluginInfo(*common.GetPluginInfoRequest) (*common.GetPluginInfoResponse, error)
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
	node_agent_proto.RegisterWorkloadAttestorServer(s, &GRPCServer{WorkloadAttestorImpl: p.WorkloadAttestorImpl})
	return nil
}

func (p WorkloadAttestorPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: node_agent_proto.NewWorkloadAttestorClient(c)}, nil
}
