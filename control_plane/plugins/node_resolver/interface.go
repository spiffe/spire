package noderesolver

import (
	"net/rpc"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/sri/pkg/common"
	"github.com/spiffe/sri/pkg/common/plugin"
	"google.golang.org/grpc"
)

// Handshake is a common handshake that is shared between noderesolution and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "NodeResolver",
	MagicCookieValue: "NodeResolver",
}

type NodeResolver interface {
	Configure(config string) ([]string, error)
	GetPluginInfo() (*sriplugin.GetPluginInfoResponse, error)
	Resolve([]string) (map[string]*common.Selectors, error)
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
	RegisterNodeResolverServer(s, &GRPCServer{NodeResolverImpl: p.NodeResolverImpl})
	return nil
}

func (p NodeResolverPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewNodeResolverClient(c)}, nil
}
