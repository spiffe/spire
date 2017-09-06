package main

import (
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/pkg/server/upstreamca"
	"github.com/spiffe/spire/plugin/server/upstreamca-memory/pkg"
	"log"
)

func main() {
	log.Print("Starting plugin")

	ca, err := pkg.NewWithDefault("../../plugin/server/upstreamca-memory/pkg/_test_data/keys/private_key.pem", "../../plugin/server/upstreamca-memory/pkg/_test_data/keys/cert.pem")
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
