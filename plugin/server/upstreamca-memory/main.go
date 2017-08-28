package main

import (
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/sri/pkg/server/upstreamca"
	"github.com/spiffe/sri/plugin/server/upstreamca-memory/pkg"
)

func main() {
	ca, err := pkg.NewWithDefault()
	if err != nil {
		panic(err.Error())
	}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: upstreamca.Handshake,
		Plugins: map[string]plugin.Plugin{
			"upstreamca": upstreamca.Plugin{Delegate: ca},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
