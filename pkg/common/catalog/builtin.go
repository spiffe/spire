package catalog

import (
	"context"
	"sync"

	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/zeebo/errs"
	"google.golang.org/grpc"
)

type BuiltInPlugin struct {
	Log          logrus.FieldLogger
	Plugin       Plugin
	HostServices []HostServiceServer
}

// LoadBuiltIn loads a builtin plugin.
func LoadBuiltInPlugin(ctx context.Context, builtIn BuiltInPlugin) (plugin *CatalogPlugin, err error) {
	if builtIn.Log == nil {
		builtIn.Log = newDiscardingLogger()
	}

	pluginClient := builtIn.Plugin.Plugin.PluginClient()
	knownServices := make([]ServiceClient, 0, len(builtIn.Plugin.Services))
	for _, service := range builtIn.Plugin.Services {
		knownServices = append(knownServices, service.ServiceClient())
	}

	var wg sync.WaitGroup
	// create a pipe from the builtin to the host
	hostNet := NewPipeNet()
	defer func() {
		if err != nil {
			hostNet.Close()
		}
	}()

	// create a host server to serve host services.
	hostServer := NewHostServer(builtIn.Plugin.Name, nil, builtIn.HostServices)
	defer func() {
		if err != nil {
			hostServer.Stop()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		hostServer.Serve(hostNet)
	}()

	// dial the host. the address is ignored.
	hostConn, err := grpc.Dial("host", grpc.WithInsecure(), grpc.WithDialer(hostNet.Dial))
	if err != nil {
		return nil, errs.Wrap(err)
	}
	defer func() {
		if err != nil {
			hostConn.Close()
		}
	}()

	// create a pipe from the host to the builtin
	builtInNet := NewPipeNet()
	defer func() {
		if err != nil {
			builtInNet.Close()
		}
	}()

	// create a gRPC server to serve the plugin and services over
	builtInServer := newBuiltInServer()
	defer func() {
		if err != nil {
			builtInServer.Stop()
		}
	}()

	logger := (&log.HCLogAdapter{
		Log:  builtIn.Log,
		Name: "builtin",
	}).Named(builtIn.Plugin.Name)

	initPluginServer(
		builtInServer,
		&builtInDialer{hostConn: hostConn},
		logger,
		builtIn.Plugin.Plugin,
		builtIn.Plugin.Services,
	)

	// now start the built in server
	wg.Add(1)
	go func() {
		defer wg.Done()
		builtInServer.Serve(builtInNet)
	}()

	// dial the builtin. the address is ignored.
	builtInConn, err := grpc.Dial("builtin", grpc.WithInsecure(), grpc.WithDialer(builtInNet.Dial))
	if err != nil {
		return nil, errs.Wrap(err)
	}
	defer func() {
		if err != nil {
			builtInConn.Close()
		}
	}()

	plugin, err = newCatalogPlugin(ctx, builtInConn, catalogPluginConfig{
		Log:           builtIn.Log,
		Name:          builtIn.Plugin.Name,
		Plugin:        pluginClient,
		KnownServices: knownServices,
		HostServices:  builtIn.HostServices,
	})
	if err != nil {
		return nil, err
	}
	plugin.closer = func() {
		builtInConn.Close()
		builtInServer.Stop()
		hostConn.Close()
		hostServer.Stop()
		wg.Wait()
	}
	return plugin, nil
}

func newBuiltInServer() *grpc.Server {
	return grpc.NewServer(
		grpc.StreamInterceptor(grpc_recovery.StreamServerInterceptor()),
		grpc.UnaryInterceptor(grpc_recovery.UnaryServerInterceptor()),
	)
}

type builtInDialer struct {
	hostConn *grpc.ClientConn
}

func (d *builtInDialer) DialHost() (*grpc.ClientConn, error) {
	return d.hostConn, nil
}
