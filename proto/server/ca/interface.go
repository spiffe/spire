package ca

import (
	"net/rpc"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	spi "github.com/spiffe/spire/proto/common/plugin"
)

// Handshake is a common handshake that is shared between noderesolution and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "ServerCA",
	MagicCookieValue: "ServerCA",
}

type ServerCa interface {
	Configure(request *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
	GetPluginInfo(*spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error)
	SignCsr(*SignCsrRequest) (*SignCsrResponse, error)
	GenerateCsr(*GenerateCsrRequest) (*GenerateCsrResponse, error)
	FetchCertificate(request *FetchCertificateRequest) (*FetchCertificateResponse, error)
	LoadCertificate(*LoadCertificateRequest) (*LoadCertificateResponse, error)
}

type ServerCaPlugin struct {
	ServerCaImpl ServerCa
}

func (p ServerCaPlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p ServerCaPlugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p ServerCaPlugin) GRPCServer(s *grpc.Server) error {
	RegisterServerCAServer(s, &GRPCServer{ServerCaImpl: p.ServerCaImpl})
	return nil
}

func (p ServerCaPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewServerCAClient(c)}, nil
}
