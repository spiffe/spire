package nodeattestor

import (
	"net/rpc"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	spi "github.com/spiffe/spire/proto/common/plugin"
)

//Handshake is a common handshake that is shared by the plugin and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "NodeAttestor",
	MagicCookieValue: "NodeAttestor",
}

type NodeAttestor interface {
	Attest(*AttestRequest) (*AttestResponse, error)
	Configure(*spi.ConfigureRequest) (*spi.ConfigureResponse, error)
	GetPluginInfo(*spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error)
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
	RegisterNodeAttestorServer(s, &GRPCServer{NodeAttestorImpl: p.NodeAttestorImpl})
	return nil
}

func (p NodeAttestorPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewNodeAttestorClient(c)}, nil
}
