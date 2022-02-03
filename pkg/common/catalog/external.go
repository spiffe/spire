package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	goplugin "github.com/hashicorp/go-plugin"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/private"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/zeebo/errs"
	"google.golang.org/grpc"
)

type externalConfig struct {
	// Name of the plugin
	Name string

	// Type is the plugin type (e.g. KeyManager)
	Type string

	// Path is the path on disk to the plugin.
	Path string

	// Args are the command line arguments to supply to the plugin
	Args []string

	// Checksum is the hex-encoded SHA256 hash of the plugin binary.
	Checksum string

	// Log is the logger to be wired to the external plugin.
	Log logrus.FieldLogger

	// HostServices are the host service servers provided to the plugin.
	HostServices []pluginsdk.ServiceServer
}

func loadExternal(ctx context.Context, config externalConfig) (*pluginImpl, error) {
	// TODO: honor context cancellation... unfortunately go-plugin doesn't seem
	// to give us a mechanism for this, so we'd have to spin up some goroutine
	// to watch for cancellation and start killing clients and closing
	// connections and the like.

	// Resolve path to an absolute path. We don't want to rely on PATH
	// environment lookups for security reasons.
	path, err := filepath.Abs(config.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve plugin path: %w", err)
	}

	cmd := pluginCmd(path, config.Args...)

	var secureConfig *goplugin.SecureConfig
	if config.Checksum != "" {
		secureConfig, err = buildSecureConfig(config.Checksum)
		if err != nil {
			return nil, err
		}
	} else {
		config.Log.Warn("Plugin checksum not configured")
	}

	logger := log.NewHCLogAdapter(
		config.Log,
		config.Name,
	)

	// Start the external plugin.
	pluginClient := goplugin.NewClient(&goplugin.ClientConfig{
		HandshakeConfig: goplugin.HandshakeConfig{
			ProtocolVersion:  1,
			MagicCookieKey:   config.Type,
			MagicCookieValue: config.Type,
		},
		Cmd: cmd,
		// TODO: Enable AutoMTLS if it is fixed to work with brokering.
		// See https://github.com/hashicorp/go-plugin/issues/109
		AutoMTLS:         false,
		AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC},
		Plugins: map[string]goplugin.Plugin{
			config.Name: &hcClientPlugin{config: config},
		},
		Logger:       logger,
		SecureConfig: secureConfig,
	})

	// Ensure the loaded plugin is killed if there is a failure.
	defer func() {
		if err != nil {
			pluginClient.Kill()
		}
	}()

	// Create the GRPC client and ensure it is closed on error.
	grpcClient, err := pluginClient.Client()
	if err != nil {
		return nil, fmt.Errorf("failed to launch plugin: %w", err)
	}
	defer func() {
		if err != nil {
			grpcClient.Close()
		}
	}()

	// Dispense the client, which invokes the GRPCClient method in the
	// hcClientPlugin. The result of that method call is returned here, which
	// is coerced back into the correct type.
	rawPlugin, err := grpcClient.Dispense(config.Name)
	if err != nil {
		return nil, err
	}

	plugin, ok := rawPlugin.(*hcPlugin)
	if !ok {
		// Purely defensive. This should never happen since we control what
		// gets returned from hcClientPlugin.
		return nil, fmt.Errorf("expected %T, got %T", plugin, rawPlugin)
	}

	// Plugin has been loaded and initialized. Ensure the plugin client is
	// killed when the plugin is closed.
	plugin.closers = append(plugin.closers, closerFunc(pluginClient.Kill))

	info := pluginInfo{
		name: config.Name,
		typ:  config.Type,
	}

	return newPlugin(ctx, plugin.conn, info, config.Log, plugin.closers, config.HostServices)
}

type hcClientPlugin struct {
	goplugin.NetRPCUnsupportedPlugin

	config externalConfig
}

var _ goplugin.GRPCPlugin = (*hcClientPlugin)(nil)

func (p *hcClientPlugin) GRPCServer(b *goplugin.GRPCBroker, s *grpc.Server) error {
	return errors.New("not implemented host side")
}

func (p *hcClientPlugin) GRPCClient(ctx context.Context, b *goplugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	// Manually start up the server via b.Accept since b.AcceptAndServe does
	// some logging we don't care for. Although b.AcceptAndServe is currently
	// the only way to feed the TLS config to the brokered connection, AutoMTLS
	// does not work yet anyway, so it is a moot point.
	listener, err := b.Accept(private.HostServiceProviderID)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	server := newHostServer(p.config.Name, p.config.HostServices)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			p.config.Log.WithError(err).Error("Host services server failed")
			c.Close()
		}
	}()

	ctx, cancel := context.WithCancel(ctx)
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		if !gracefulStopWithTimeout(server) {
			p.config.Log.Warn("Forced timed-out host service server to stop")
		}
	}()

	return &hcPlugin{
		conn:    c,
		closers: closerFuncs(cancel, wg.Wait),
	}, nil
}

type hcPlugin struct {
	conn    grpc.ClientConnInterface
	closers closerGroup
}

func buildSecureConfig(checksum string) (*goplugin.SecureConfig, error) {
	sum, err := hex.DecodeString(checksum)
	if err != nil {
		return nil, errors.New("checksum is not a valid hex string")
	}

	hash := sha256.New()
	if len(sum) != hash.Size() {
		return nil, fmt.Errorf("expected checksum of length %d; got %d", hash.Size()*2, len(sum)*2)
	}

	return &goplugin.SecureConfig{
		Checksum: sum,
		Hash:     sha256.New(),
	}, nil
}
