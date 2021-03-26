// +build ignore

package main

import (
	"context"
	"errors"

	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

func main() {
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: goplugin.HandshakeConfig{
			ProtocolVersion:  99,
			MagicCookieKey:   "BAD",
			MagicCookieValue: "BAD",
		},
		Plugins: map[string]goplugin.Plugin{
			"BAD": &hcServerPlugin{},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}

type hcServerPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
}

func (p *hcServerPlugin) GRPCServer(b *goplugin.GRPCBroker, s *grpc.Server) (err error) {
	return nil
}

func (p *hcServerPlugin) GRPCClient(ctx context.Context, b *goplugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return nil, errors.New("unimplemented")
}
