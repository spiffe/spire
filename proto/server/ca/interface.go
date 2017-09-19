package ca

import (
	"net/rpc"

	"google.golang.org/grpc"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/pkg/common/plugin"
)

// Handshake is a common handshake that is shared between noderesolution and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "ControlPlaneCA",
	MagicCookieValue: "ControlPlaneCA",
}

type ControlPlaneCa interface {
	Configure(request *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error)
	GetPluginInfo(*sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error)
	SignCsr(*SignCsrRequest) (*SignCsrResponse, error)
	GenerateCsr(*GenerateCsrRequest) (*GenerateCsrResponse, error)
	FetchCertificate(request *FetchCertificateRequest) (*FetchCertificateResponse, error)
	LoadCertificate(*LoadCertificateRequest) (*LoadCertificateResponse, error)
}

type ControlPlaneCaPlugin struct {
	ControlPlaneCaImpl ControlPlaneCa
}

func (p ControlPlaneCaPlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p ControlPlaneCaPlugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p ControlPlaneCaPlugin) GRPCServer(s *grpc.Server) error {
	RegisterControlPlaneCAServer(s, &GRPCServer{ControlPlaneCaImpl: p.ControlPlaneCaImpl})
	return nil
}

func (p ControlPlaneCaPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewControlPlaneCAClient(c)}, nil
}
