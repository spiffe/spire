package jointoken

import (
	"context"
	"errors"

	"github.com/spiffe/spire/pkg/common/catalog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/nodeattestor"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *JoinTokenPlugin) catalog.Plugin {
	return catalog.MakePlugin("join_token",
		nodeattestor.PluginServer(p),
	)
}

type JoinTokenPlugin struct{}

func New() *JoinTokenPlugin {
	return &JoinTokenPlugin{}
}

func (p *JoinTokenPlugin) Attest(stream nodeattestor.NodeAttestor_AttestServer) error {
	return errors.New("join token attestation is currently implemented within the server")
}

func (p *JoinTokenPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (p *JoinTokenPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}
