package upstreamca

import (
	"net/rpc"

	"google.golang.org/grpc"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/control-plane/plugins/upstream_ca/proto"
)

// Handshake is a common handshake that is shared between noderesolution and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "upstreamca_handshake",
	MagicCookieValue: "upstreamca",
}

// PluginMap is the map of plugins we can dispense.
var PluginMap = map[string]plugin.Plugin{
	"upstreamca": &UpstreamCaPlugin{},
}

type UpstreamCa interface {
	SubmitCSR([]byte) (*proto.SubmitCSRResponse, error)
}

type UpstreamCaPlugin struct {
	UpstreamCaImpl UpstreamCa
}

func (p UpstreamCaPlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p UpstreamCaPlugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p UpstreamCaPlugin) GRPCServer(s *grpc.Server) error {
	proto.RegisterNodeServer(s, &GRPCServer{UpstreamCaImpl: p.UpstreamCaImpl})
	return nil
}

func (p UpstreamCaPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: proto.NewNodeClient(c)}, nil
}
