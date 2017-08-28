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

type Interface interface {
	Configure(config string) ([]string, error)
	GetPluginInfo() (*sriplugin.GetPluginInfoResponse, error)
	SubmitCSR([]byte) (*SubmitCSRResponse, error)
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
	RegisterUpstreamCAServer(s, &grpcServer{delegate: p.Delegate})
	return nil
}

func (p Plugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &grpcClient{client: NewUpstreamCAClient(c)}, nil
}
