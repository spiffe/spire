package main

import (
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/control-plane/plugins/noderesolver"
	"github.com/spiffe/control-plane/plugins/noderesolver/proto"
)


func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: noderesolver.Handshake,
		Plugins: map[string]plugin.Plugin{
			"noderesolver": noderesolver.NodeResolutionPlugin{NodeResolutionImpl: &NoOp{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}