package workloadattestor

import (
	"net/rpc"

	"google.golang.org/grpc"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/node-agent/plugins/common/proto"
	"github.com/spiffe/node-agent/plugins/workload_attestor/proto"
)

//Handshake is a common handshake that is shared by the plugin and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "workloadattestor_handshake",
	MagicCookieValue: "workloadattestor",
}

//PluginMap is the map of plugins we can dispense.
var PluginMap = map[string]plugin.Plugin{
	"workloadattestor": &WorkloadAttestorPlugin{},
}

type WorkloadAttestor interface {
	Attest(*proto.AttestRequest) (*proto.AttestResponse, error)
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
	proto.RegisterWorkloadAttestorServer(s, &GRPCServer{WorkloadAttestorImpl: p.WorkloadAttestorImpl})
	return nil
}

func (p WorkloadAttestorPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: proto.NewWorkloadAttestorClient(c)}, nil
}
