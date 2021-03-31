package noop

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	noderesolverv0 "github.com/spiffe/spire/proto/spire/plugin/server/noderesolver/v0"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *NoOp) catalog.Plugin {
	return catalog.MakePlugin("noop",
		noderesolverv0.PluginServer(p),
	)
}

type NoOp struct {
	noderesolverv0.UnsafeNodeResolverServer
}

func New() *NoOp {
	return &NoOp{}
}

func (NoOp) Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (NoOp) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (NoOp) Resolve(context.Context, *noderesolverv0.ResolveRequest) (*noderesolverv0.ResolveResponse, error) {
	return &noderesolverv0.ResolveResponse{}, nil
}
