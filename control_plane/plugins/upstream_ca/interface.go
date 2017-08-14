package upstreamca

import (
	"net/rpc"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/sri/control_plane/plugins/common/proto"
	"github.com/spiffe/sri/control_plane/plugins/upstream_ca/proto"
	"google.golang.org/grpc"
)

// Handshake is a common handshake that is shared between noderesolution and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "UpstreamCA",
	MagicCookieValue: "UpstreamCA",
}

type UpstreamCa interface {
	Configure(config string) ([]string, error)
	GetPluginInfo() (*common.GetPluginInfoResponse, error)
	SubmitCSR([]byte) (*control_plane_proto.SubmitCSRResponse, error)
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
	control_plane_proto.RegisterUpstreamCAServer(s, &GRPCServer{UpstreamCaImpl: p.UpstreamCaImpl})
	return nil
}

func (p UpstreamCaPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: control_plane_proto.NewUpstreamCAClient(c)}, nil
}
