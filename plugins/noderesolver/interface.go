package noderesolver

import (
	"net/rpc"

	"google.golang.org/grpc"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/control-plane/plugins/noderesolver/proto"
)

// Handshake is a common handshake that is shared between noderesolution and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "noderesolution_handshake",
	MagicCookieValue: "noderesolution",
}

// PluginMap is the map of plugins we can dispense.
var PluginMap = map[string]plugin.Plugin{
	"node_resolution_aws": &NodeResolutionPlugin{},
}

type NodeResolution interface {
	Resolve([]string) (map[string]*proto.NodeResolutionList, error)
	Configure(config string) error
}

type NodeResolutionPlugin struct {
	NodeResolutionImpl NodeResolution
}

func (p NodeResolutionPlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p NodeResolutionPlugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p NodeResolutionPlugin) GRPCServer(s *grpc.Server) error {
	proto.RegisterNodeServer(s, &GRPCServer{NodeResolutionImpl: p.NodeResolutionImpl})
	return nil
}

func (p NodeResolutionPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: proto.NewNodeClient(c)}, nil
}
