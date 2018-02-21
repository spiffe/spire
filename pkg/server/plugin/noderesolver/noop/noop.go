package noop

import (
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/noderesolver"
)

type NoOp struct{}

func (NoOp) Configure(*spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (NoOp) GetPluginInfo(*spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (NoOp) Resolve(physicalSpiffeIdList []string) (resolutions map[string]*common.Selectors, err error) {
	return resolutions, nil
}

func New() noderesolver.NodeResolver {
	return &NoOp{}
}
