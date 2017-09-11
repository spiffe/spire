package main

import (
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/pkg/server/upstreamca"
	"github.com/spiffe/spire/plugin/server/upstreamca-memory/pkg"
	"log"
)

func main() {
	log.Print("Starting plugin")

	ca := pkg.NewEmpty()
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: upstreamca.Handshake,
		Plugins: map[string]plugin.Plugin{
			"upstreamca": upstreamca.UpstreamCaPlugin{UpstreamCaImpl: ca},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
