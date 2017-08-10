package upstreamca

import (
	"net/rpc"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/control-plane/plugins/common/proto"
	"github.com/spiffe/control-plane/plugins/upstream_ca/proto"
	"google.golang.org/grpc"
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
	Configure(config string) ([]string, error)
	GetPluginInfo() (*common.GetPluginInfoResponse, error)
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
	proto.RegisterUpstreamCAServer(s, &GRPCServer{UpstreamCaImpl: p.UpstreamCaImpl})
	return nil
}

func (p UpstreamCaPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: proto.NewUpstreamCAClient(c)}, nil
}
