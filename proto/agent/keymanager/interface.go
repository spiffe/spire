package keymanager

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
	MagicCookieKey:   "KeyManager",
	MagicCookieValue: "KeyManager",
}

type KeyManager interface {
	GenerateKeyPair(context.Context, *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error)
	FetchPrivateKey(context.Context, *FetchPrivateKeyRequest) (*FetchPrivateKeyResponse, error)
	Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
	GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error)
}

type KeyManagerPlugin struct {
	KeyManagerImpl KeyManager
}

func (p KeyManagerPlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p KeyManagerPlugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p KeyManagerPlugin) GRPCServer(s *grpc.Server) error {
	RegisterKeyManagerServer(s, p.KeyManagerImpl)
	return nil
}

func (p KeyManagerPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewKeyManagerClient(c)}, nil
}
