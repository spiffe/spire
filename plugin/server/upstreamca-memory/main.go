package main

import (
	"log"

	"github.com/hashicorp/go-plugin"

	"github.com/spiffe/spire/plugin/server/upstreamca-memory/pkg"
	"github.com/spiffe/spire/proto/server/upstreamca"
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
