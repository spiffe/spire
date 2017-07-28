package controlplaneca

import (
	"net/rpc"

	"google.golang.org/grpc"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/control-plane/plugins/common/proto"
	"github.com/spiffe/control-plane/plugins/control_plane_ca/proto"
)

// Handshake is a common handshake that is shared between noderesolution and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "controlplaneca_handshake",
	MagicCookieValue: "controlplaneca",
}

// PluginMap is the map of plugins we can dispense.
var PluginMap = map[string]plugin.Plugin{
	"controlplaneca": &ControlPlaneCaPlugin{},
}

type ControlPlaneCa interface {
	Configure(config string) ([]string, error)
	GetPluginInfo() (*common.GetPluginInfoResponse, error)
	SignCsr([]byte) ([]byte, error)
	GenerateCsr() ([]byte, error)
	FetchCertificate() ([]byte, error)
	LoadCertificate([]byte) error
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
	proto.RegisterControlPlaneCAServer(s, &GRPCServer{ControlPlaneCaImpl: p.ControlPlaneCaImpl})
	return nil
}

func (p ControlPlaneCaPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: proto.NewControlPlaneCAClient(c)}, nil
}
