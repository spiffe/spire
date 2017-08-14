package nodeattestor

import (
	"net/rpc"

	"google.golang.org/grpc"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/sri/control_plane/plugins/common/proto"

	"github.com/spiffe/sri/control_plane/plugins/node_attestor/proto"
)

//Handshake is a common handshake that is shared by the plugin and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "NodeAttestor",
	MagicCookieValue: "NodeAttestor",
}

type NodeAttestor interface {
	Configure(config string) ([]string, error)
	GetPluginInfo() (*common.GetPluginInfoResponse, error)
	Attest(request *proto.AttestRequest) (*proto.AttestResponse, error)
}

type NodeAttestorPlugin struct {
	NodeAttestorImpl NodeAttestor
}

func (p NodeAttestorPlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p NodeAttestorPlugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p NodeAttestorPlugin) GRPCServer(s *grpc.Server) error {
	proto.RegisterNodeAttestorServer(s, &GRPCServer{NodeAttestorImpl: p.NodeAttestorImpl})
	return nil
}

func (p NodeAttestorPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: proto.NewNodeAttestorClient(c)}, nil
}
