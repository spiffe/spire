package ca

import (
	"net/rpc"

	"google.golang.org/grpc"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/sri/pkg/common/plugin"
)

// Handshake is a common handshake that is shared between noderesolution and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "ControlPlaneCA",
	MagicCookieValue: "ControlPlaneCA",
}

type Interface interface {
	Configure(config string) ([]string, error)
	GetPluginInfo() (*sriplugin.GetPluginInfoResponse, error)
	SignCsr([]byte) ([]byte, error)
	GenerateCsr() ([]byte, error)
	FetchCertificate() ([]byte, error)
	LoadCertificate([]byte) error
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
	RegisterControlPlaneCAServer(s, &grpcServer{delegate: p.Delegate})
	return nil
}

func (p Plugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &grpcClient{client: NewControlPlaneCAClient(c)}, nil
}
