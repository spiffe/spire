package catalog

import (
	"context"
	"io"
	"sync"

	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/zeebo/errs"
	"google.golang.org/grpc"
)

type BuiltInPlugin struct {
	Log          logrus.FieldLogger
	Plugin       Plugin
	HostServices []HostServiceServer
}

// LoadBuiltIn loads a builtin plugin.
func LoadBuiltInPlugin(ctx context.Context, builtin BuiltInPlugin) (plugin *LoadedPlugin, err error) {
	if builtin.Log == nil {
		builtin.Log = newDiscardingLogger()
	}

	// The stutter on this statement is unforgivable but it is the only
	// statement where this happens and renaming the fields would break
	// consistency with other field names.
	pluginClient := builtin.Plugin.Plugin.PluginClient()

	knownServices := make([]ServiceClient, 0, len(builtin.Plugin.Services))
	for _, service := range builtin.Plugin.Services {
		knownServices = append(knownServices, service.ServiceClient())
	}

	// set up a group of closers we'll build as we go. if there is an error
	// we'll close everything so far, otherwise it will be used as the
	// closer for the catalog plugin.
	var wg sync.WaitGroup
	closers := newCloserGroup(wg.Wait)
	defer func() {
		if err != nil {
			closers.Close()
		}
	}()

	// create a pipe from the builtin to the host
	hostNet := NewPipeNet()
	closers.AddCloser(hostNet)

	// create a host server to serve host services.
	hostServer := NewHostServer(builtin.Plugin.Name, nil, builtin.HostServices)
	closers.AddFunc(hostServer.Stop)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := hostServer.Serve(hostNet); err != nil {
			builtin.Log.WithError(err).Warn("host server failed to serve")
		}
	}()

	// dial the host. the address is ignored.
	hostConn, err := grpc.Dial("host", grpc.WithInsecure(), grpc.WithContextDialer(hostNet.DialContext))
	if err != nil {
		return nil, errs.Wrap(err)
	}
	closers.AddCloser(hostConn)

	// create a pipe from the host to the builtin
	builtinNet := NewPipeNet()
	closers.AddCloser(builtinNet)

	// create a gRPC server to serve the plugin and services over
	builtinServer := newBuiltInServer()
	closers.AddFunc(builtinServer.Stop)

	logger := log.NewHCLogAdapter(
		builtin.Log,
		telemetry.PluginBuiltIn,
	).Named(builtin.Plugin.Name)

	initPluginServer(
		builtinServer,
		&builtinDialer{hostConn: hostConn},
		logger,
		builtin.Plugin.Plugin,
		builtin.Plugin.Services,
	)

	// now start the built in server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := builtinServer.Serve(builtinNet); err != nil {
			builtin.Log.WithError(err).Warn("builtin server failed to serve")
		}
	}()

	// dial the builtin. the address is ignored.
	builtinConn, err := grpc.Dial("builtin", grpc.WithInsecure(), grpc.WithContextDialer(builtinNet.DialContext))
	if err != nil {
		return nil, errs.Wrap(err)
	}
	closers.AddCloser(builtinConn)

	plugin, err = newCatalogPlugin(ctx, builtinConn, catalogPluginConfig{
		Log:           builtin.Log,
		Name:          builtin.Plugin.Name,
		BuiltIn:       true,
		Plugin:        pluginClient,
		KnownServices: knownServices,
		HostServices:  builtin.HostServices,
	})
	if err != nil {
		return nil, err
	}

	plugin.closer = closers.Close
	return plugin, nil
}

func newBuiltInServer() *grpc.Server {
	return grpc.NewServer(
		grpc.StreamInterceptor(grpc_recovery.StreamServerInterceptor()),
		grpc.UnaryInterceptor(grpc_recovery.UnaryServerInterceptor()),
	)
}

type builtinDialer struct {
	hostConn *grpc.ClientConn
}

func (d *builtinDialer) DialHost() (*grpc.ClientConn, error) {
	return d.hostConn, nil
}

type closerGroup struct {
	closers []func()
}

func newCloserGroup(closers ...func()) *closerGroup {
	return &closerGroup{
		closers: closers,
	}
}

func (cg *closerGroup) AddFunc(closer func()) {
	cg.closers = append(cg.closers, closer)
}

func (cg *closerGroup) AddCloser(closer io.Closer) {
	cg.AddFunc(func() {
		// purposefully discard the error
		closer.Close()
	})
}

func (cg *closerGroup) Close() {
	// close in reverse order
	for i := len(cg.closers) - 1; i >= 0; i-- {
		cg.closers[i]()
	}
}
