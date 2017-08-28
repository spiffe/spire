package nodeattestor

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
	MagicCookieKey:   "NodeAttestor",
	MagicCookieValue: "NodeAttestor",
}

type Interface interface {
	FetchAttestationData(*FetchAttestationDataRequest) (*FetchAttestationDataResponse, error)
	Configure(*sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error)
	GetPluginInfo(*sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error)
}

type Plugin struct {
	Delegate Interface
}

func (p Plugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p Plugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p Plugin) GRPCServer(s *grpc.Server) error {
	RegisterNodeAttestorServer(s, &grpcServer{delegate: p.Delegate})
	return nil
}

func (p Plugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &grpcClient{client: NewNodeAttestorClient(c)}, nil
}
