// +build ignore

// This file is used during testing. It is built as an external binary and
// loaded as an external plugin.
package main

import (
	"context"
	"errors"

	goplugin "github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/pkg/common/catalog/test"
	"google.golang.org/grpc"
)

func main() {
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: goplugin.HandshakeConfig{
			ProtocolVersion:  1,
			MagicCookieKey:   "TestPlugin",
			MagicCookieValue: "TestPlugin",
		},
		Plugins: map[string]goplugin.Plugin{
			"oldplugin": grpcPlugin{},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}

type grpcPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
}

func (grpcPlugin) GRPCServer(b *goplugin.GRPCBroker, s *grpc.Server) error {
	test.RegisterTestPluginServer(s, test.NewTestPlugin())
	return nil
}

func (grpcPlugin) GRPCClient(ctx context.Context, b *goplugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return nil, errors.New("unimplemented")
}
