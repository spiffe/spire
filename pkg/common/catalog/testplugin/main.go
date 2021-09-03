// +build ignore

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	goplugin "github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	"github.com/spiffe/spire/pkg/common/catalog/testplugin"
	"google.golang.org/grpc"
)

var (
	modeFlag           = flag.String("mode", "good", "plugin mode to use (one of [good, bad])")
	registerConfigFlag = flag.Bool("registerConfig", false, "register the configuration service")
)

func main() {
	flag.Parse()

	switch *modeFlag {
	case "good":
		flag.Parse()
		builtIn := testplugin.BuiltIn(*registerConfigFlag)
		pluginmain.Serve(
			builtIn.Plugin,
			builtIn.Services...,
		)
	case "bad":
		goplugin.Serve(&goplugin.ServeConfig{
			HandshakeConfig: goplugin.HandshakeConfig{
				ProtocolVersion:  99,
				MagicCookieKey:   "BAD",
				MagicCookieValue: "BAD",
			},
			Plugins: map[string]goplugin.Plugin{
				"BAD": &badHCServerPlugin{},
			},
			GRPCServer: goplugin.DefaultGRPCServer,
		})
	default:
		fmt.Fprintln(os.Stderr, "bad value for mode: must be one of [good,bad]")
		os.Exit(1)
	}
}

type badHCServerPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
}

func (p *badHCServerPlugin) GRPCServer(b *goplugin.GRPCBroker, s *grpc.Server) (err error) {
	return nil
}

func (p *badHCServerPlugin) GRPCClient(ctx context.Context, b *goplugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return nil, errors.New("unimplemented")
}
