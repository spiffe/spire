package main

import (
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/sri/pkg/server/upstreamca"
	"github.com/spiffe/sri/plugin/server/upstreamca-memory/pkg"
)

func main() {
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
