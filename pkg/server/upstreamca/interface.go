package upstreamca

import (
	"net/rpc"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/sri/pkg/common/plugin"
	"google.golang.org/grpc"
)

// Handshake is a common handshake that is shared between noderesolution and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "UpstreamCA",
	MagicCookieValue: "UpstreamCA",
}

type UpstreamCa interface {
	Configure(request *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error)
	GetPluginInfo() (*sriplugin.GetPluginInfoResponse, error)
	SubmitCSR([]byte) (*SubmitCSRResponse, error)
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
	RegisterUpstreamCAServer(s, &GRPCServer{UpstreamCaImpl: p.UpstreamCaImpl})
	return nil
}

func (p UpstreamCaPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewUpstreamCAClient(c)}, nil
}
