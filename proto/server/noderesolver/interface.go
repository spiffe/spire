package noderesolver

import (
	"net/rpc"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	context "golang.org/x/net/context"
	"google.golang.org/grpc"

	spi "github.com/spiffe/spire/proto/common/plugin"
)

// Handshake is a common handshake that is shared between noderesolution and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "NodeResolver",
	MagicCookieValue: "NodeResolver",
}

type NodeResolver interface {
	Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
	GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error)
	Resolve(context.Context, *ResolveRequest) (*ResolveResponse, error)
}

type NodeResolverPlugin struct {
	NodeResolverImpl NodeResolver
}

func (p NodeResolverPlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p NodeResolverPlugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p NodeResolverPlugin) GRPCServer(s *grpc.Server) error {
	RegisterNodeResolverServer(s, p.NodeResolverImpl)
	return nil
}

func (p NodeResolverPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewNodeResolverClient(c)}, nil
}
