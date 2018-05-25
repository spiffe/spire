package workloadattestor

import (
	"net/rpc"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	context "golang.org/x/net/context"
	"google.golang.org/grpc"

	spi "github.com/spiffe/spire/proto/common/plugin"
)

//Handshake is a common handshake that is shared by the plugin and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "WorkloadAttestor",
	MagicCookieValue: "WorkloadAttestor",
}

type WorkloadAttestor interface {
	Attest(context.Context, *AttestRequest) (*AttestResponse, error)
	Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
	GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error)
}

type WorkloadAttestorPlugin struct {
	WorkloadAttestorImpl WorkloadAttestor
}

func (p WorkloadAttestorPlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p WorkloadAttestorPlugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p WorkloadAttestorPlugin) GRPCServer(s *grpc.Server) error {
	RegisterWorkloadAttestorServer(s, p.WorkloadAttestorImpl)
	return nil
}

func (p WorkloadAttestorPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewWorkloadAttestorClient(c)}, nil
}
