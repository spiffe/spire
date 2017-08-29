package main

import (
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/sri/pkg/common"
	"github.com/spiffe/sri/pkg/common/plugin"
	"github.com/spiffe/sri/pkg/server/noderesolver"
)

type NoOp struct{}

func (NoOp) Configure(*sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	return &sriplugin.ConfigureResponse{}, nil
}

func (NoOp) GetPluginInfo() (*sriplugin.GetPluginInfoResponse, error) {
	return nil, nil
}

func (NoOp) Resolve(physicalSpiffeIdList []string) (resolutions map[string]*common.Selectors, err error) {
	return resolutions, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: noderesolver.Handshake,
		Plugins: map[string]plugin.Plugin{
			"nr_noop": noderesolver.NodeResolverPlugin{NodeResolverImpl: &NoOp{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
