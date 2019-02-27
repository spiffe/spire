package main

import (
	"context"
	"log"

	go_plugin "github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/unix"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	spi "github.com/spiffe/spire/proto/common/plugin"
)

func main() {
	unixplugin := unix.New()
	if _, err := unixplugin.Configure(context.Background(), &spi.ConfigureRequest{}); err != nil {
		log.Fatalf("Failed to configure unix plugin: %v", err)
	}
	go_plugin.Serve(&go_plugin.ServeConfig{
		HandshakeConfig: workloadattestor.Handshake,
		Plugins: map[string]go_plugin.Plugin{
			"workloadattestor": &workloadattestor.GRPCPlugin{
				ServerImpl: &workloadattestor.GRPCServer{
					Plugin: unixplugin,
				},
			},
		},
		GRPCServer: go_plugin.DefaultGRPCServer,
	})
}
