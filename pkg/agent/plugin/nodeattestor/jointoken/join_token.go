package jointoken

import (
	"context"
	"errors"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/agent/nodeattestor"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
)

const (
	pluginName = "join_token"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *JoinTokenPlugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, nodeattestor.PluginServer(p))
}

type JoinTokenPlugin struct{}

func New() *JoinTokenPlugin {
	return &JoinTokenPlugin{}
}

func (p *JoinTokenPlugin) FetchAttestationData(stream nodeattestor.NodeAttestor_FetchAttestationDataServer) error {
	return errors.New("join token attestation is currently implemented within the agent")
}

func (p *JoinTokenPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (*JoinTokenPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}
