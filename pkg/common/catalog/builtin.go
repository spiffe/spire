package catalog

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/private"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/zeebo/errs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type BuiltIn struct {
	Name     string
	Plugin   pluginsdk.PluginServer
	Services []pluginsdk.ServiceServer
}

func MakeBuiltIn(name string, pluginServer pluginsdk.PluginServer, serviceServers ...pluginsdk.ServiceServer) BuiltIn {
	return BuiltIn{
		Name:     name,
		Plugin:   pluginServer,
		Services: serviceServers,
	}
}

type BuiltInConfig struct {
	// Log is the logger to be wired to the external plugin.
	Log logrus.FieldLogger

	// HostServices are the host service servers provided to the plugin.
	HostServices []pluginsdk.ServiceServer
}

func LoadBuiltIn(ctx context.Context, builtIn BuiltIn, config BuiltInConfig) (_ Plugin, err error) {
	return loadBuiltIn(ctx, builtIn, config)
}

func loadBuiltIn(ctx context.Context, builtIn BuiltIn, config BuiltInConfig) (_ *pluginImpl, err error) {
	builtinServer := newBuiltInServer()

	logger := log.NewHCLogAdapter(
		config.Log,
		builtIn.Name,
	)

	dialer := &builtinDialer{
		pluginName:   builtIn.Name,
		log:          config.Log,
		hostServices: config.HostServices,
	}

	var closers closerGroup
	defer func() {
		if err != nil {
			closers.Close()
		}
	}()
	closers = append(closers, dialer)

	pluginServers := append([]pluginsdk.ServiceServer{builtIn.Plugin}, builtIn.Services...)

	private.Register(builtinServer, pluginServers, logger, dialer)

	builtinConn, err := startPipeServer(builtinServer, config.Log)
	if err != nil {
		return nil, err
	}
	closers = append(closers, builtinConn)

	info := pluginInfo{
		name: builtIn.Name,
		typ:  builtIn.Plugin.Type(),
	}

	return newPlugin(ctx, builtinConn, info, config.Log, closers, config.HostServices)
}

func newBuiltInServer() *grpc.Server {
	return grpc.NewServer(
		grpc.StreamInterceptor(streamPanicInterceptor),
		grpc.UnaryInterceptor(unaryPanicInterceptor),
	)
}

type builtinDialer struct {
	pluginName   string
	log          logrus.FieldLogger
	hostServices []pluginsdk.ServiceServer
	conn         *pipeConn
}

func (d *builtinDialer) DialHost(ctx context.Context) (grpc.ClientConnInterface, error) {
	if d.conn != nil {
		return d.conn, nil
	}
	server := newHostServer(d.pluginName, d.hostServices)
	conn, err := startPipeServer(server, d.log)
	if err != nil {
		return nil, err
	}
	d.conn = conn
	return d.conn, nil
}

func (d *builtinDialer) Close() error {
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}

type pipeConn struct {
	grpc.ClientConnInterface
	io.Closer
}

func startPipeServer(server *grpc.Server, log logrus.FieldLogger) (_ *pipeConn, err error) {
	var closers closerGroup

	pipeNet := newPipeNet()
	closers = append(closers, pipeNet)

	var wg sync.WaitGroup
	closers = append(closers, closerFunc(wg.Wait), closerFunc(func() {
		if !gracefulStopWithTimeout(server) {
			log.Warn("Forced timed-out plugin server to stop")
		}
	}))

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.Serve(pipeNet); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			log.WithError(err).Error("Pipe server unexpectedly failed to serve")
		}
	}()

	// Dial the server
	conn, err := grpc.Dial("IGNORED", grpc.WithBlock(), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(pipeNet.DialContext))
	if err != nil {
		return nil, errs.Wrap(err)
	}
	closers = append(closers, conn)

	return &pipeConn{
		ClientConnInterface: conn,
		Closer:              closers,
	}, nil
}
