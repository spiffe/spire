package noop

import (
	"context"

	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/noderesolver"
)

type NoOp struct{}

func (NoOp) Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (NoOp) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (NoOp) Resolve(context.Context, *noderesolver.ResolveRequest) (*noderesolver.ResolveResponse, error) {
	return &noderesolver.ResolveResponse{}, nil
}

func New() noderesolver.NodeResolverPlugin {
	return &NoOp{}
}
