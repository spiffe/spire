package catalog

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/private"
	"github.com/spiffe/spire/pkg/common/log"
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

	builtinServer, serverCloser := newBuiltInServer(config.Log)
	closers = append(closers, serverCloser)

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

func newBuiltInServer(log logrus.FieldLogger) (*grpc.Server, io.Closer) {
	drain := &drainHandlers{}
	return grpc.NewServer(
		grpc.ChainStreamInterceptor(drain.StreamServerInterceptor, streamPanicInterceptor(log)),
		grpc.ChainUnaryInterceptor(drain.UnaryServerInterceptor, unaryPanicInterceptor(log)),
	), closerFunc(drain.Wait)
}

type builtinDialer struct {
	pluginName   string
	log          logrus.FieldLogger
	hostServices []pluginsdk.ServiceServer
	conn         *pipeConn
}

func (d *builtinDialer) DialHost(context.Context) (grpc.ClientConnInterface, error) {
	if d.conn != nil {
		return d.conn, nil
	}
	server := newHostServer(d.log, d.pluginName, d.hostServices)
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
	conn, err := grpc.Dial("IGNORED", grpc.WithBlock(), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(pipeNet.DialContext)) //nolint: staticcheck // It is going to be resolved on #5152
	if err != nil {
		return nil, err
	}
	closers = append(closers, conn)

	return &pipeConn{
		ClientConnInterface: conn,
		Closer:              closers,
	}, nil
}

type drainHandlers struct {
	wg sync.WaitGroup
}

func (d *drainHandlers) Wait() {
	done := make(chan struct{})

	go func() {
		d.wg.Wait()
		close(done)
	}()

	t := time.NewTimer(time.Minute)
	defer t.Stop()

	select {
	case <-done:
	case <-t.C:
	}
}

func (d *drainHandlers) UnaryServerInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	d.wg.Add(1)
	defer d.wg.Done()
	return handler(ctx, req)
}

func (d *drainHandlers) StreamServerInterceptor(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	d.wg.Add(1)
	defer d.wg.Done()
	return handler(srv, ss)
}
