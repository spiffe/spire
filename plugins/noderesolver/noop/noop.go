package main

import (
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/control-plane/plugins/common/proto"
	"github.com/spiffe/control-plane/plugins/noderesolver"
	"github.com/spiffe/control-plane/plugins/noderesolver/proto"
)

type NoOp struct{}

func (NoOp) Configure(config string) ([]string, error) {
	return []string{}, nil
}

func (NoOp) GetPluginInfo() (*common.GetPluginInfoResponse, error) {
	return nil, nil
}

func (NoOp) Resolve(physicalSpiffeIdList []string) (resolutions map[string]*proto.NodeResolutionList, err error) {
	return resolutions, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: noderesolver.Handshake,
		Plugins: map[string]plugin.Plugin{
			"noderesolver": noderesolver.NodeResolutionPlugin{NodeResolutionImpl: &NoOp{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
