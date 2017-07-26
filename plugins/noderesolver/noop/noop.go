package main

import (
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/control-plane/plugins/noderesolver"
	"github.com/spiffe/control-plane/plugins/noderesolver/proto"
)

type NoOp struct{}

func (NoOp) Resolve(physicalSpiffeIdList []string) (resolutions map[string]*proto.NodeResolutionList, err error) {
	return resolutions, nil
}

func (NoOp) Configure(configuration string) error {
	return nil
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
