package jointoken

import (
	"context"
	"errors"

	"github.com/spiffe/spire/pkg/common/catalog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	nodeattestorv0 "github.com/spiffe/spire/proto/spire/server/nodeattestor/v0"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin("join_token",
		nodeattestorv0.PluginServer(p),
	)
}

type Plugin struct {
	nodeattestorv0.UnsafeNodeAttestorServer
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) Attest(stream nodeattestorv0.NodeAttestor_AttestServer) error {
	return errors.New("join token attestation is currently implemented within the server")
}

func (p *Plugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (p *Plugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}
