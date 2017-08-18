package main

import (
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/sri/control_plane/plugins/common/proto"
	"github.com/spiffe/sri/control_plane/plugins/node_resolver"
	"github.com/spiffe/sri/control_plane/plugins/node_resolver/proto"
)

type NoOp struct{}

func (NoOp) Configure(config string) ([]string, error) {
	return []string{}, nil
}

func (NoOp) GetPluginInfo() (*common.GetPluginInfoResponse, error) {
	return nil, nil
}

func (NoOp) Resolve(physicalSpiffeIdList []string) (resolutions map[string]*sri_proto.NodeResolutionList, err error) {
	return resolutions, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: noderesolver.Handshake,
		Plugins: map[string]plugin.Plugin{
			"nr_noop": noderesolver.NodeResolutionPlugin{NodeResolutionImpl: &NoOp{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
