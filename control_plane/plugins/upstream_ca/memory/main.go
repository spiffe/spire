package main

import (
	plugin "github.com/hashicorp/go-plugin"
	upstreamca "github.com/spiffe/sri/control_plane/plugins/upstream_ca"
	"github.com/spiffe/sri/control_plane/plugins/upstream_ca/memory/pkg"
)

func main() {
	ca, err := pkg.NewWithDefault()
	if err != nil {
		panic(err.Error())
	}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: upstreamca.Handshake,
		Plugins: map[string]plugin.Plugin{
			"upstreamca": upstreamca.UpstreamCaPlugin{UpstreamCaImpl: ca},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
