package main

import (
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/sri/common/plugin"
	"github.com/spiffe/sri/control_plane/plugins/node_resolver"
)

type NoOp struct{}

func (NoOp) Configure(config string) ([]string, error) {
	return []string{}, nil
}

func (NoOp) GetPluginInfo() (*sriplugin.GetPluginInfoResponse, error) {
	return nil, nil
}

func (NoOp) Resolve(physicalSpiffeIdList []string) (resolutions map[string]*noderesolver.NodeResolutionList, err error) {
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
