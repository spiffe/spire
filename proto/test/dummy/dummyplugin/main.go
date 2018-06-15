package main

import (
	go_plugin "github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/proto/test/dummy"
	"github.com/spiffe/spire/proto/test/dummy/dummybuiltin"
)

func main() {
	builtIn := dummybuiltin.New()

	go_plugin.Serve(&go_plugin.ServeConfig{
		HandshakeConfig: dummy.Handshake,
		Plugins: map[string]go_plugin.Plugin{
			"dummy": &dummy.GRPCPlugin{
				ServerImpl: &dummy.GRPCServer{
					Plugin: builtIn,
				},
			},
		},
		GRPCServer: go_plugin.DefaultGRPCServer,
	})
}
