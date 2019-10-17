package noop

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/noderesolver"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *NoOp) catalog.Plugin {
	return catalog.MakePlugin("noop",
		noderesolver.PluginServer(p),
	)
}

type NoOp struct{}

func New() *NoOp {
	return &NoOp{}
}

func (NoOp) Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (NoOp) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (NoOp) Resolve(context.Context, *noderesolver.ResolveRequest) (*noderesolver.ResolveResponse, error) {
	return &noderesolver.ResolveResponse{}, nil
}
