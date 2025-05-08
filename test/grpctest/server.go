package grpctest

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"testing"

	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type ServerOption = func(*serverConfig)

type Server struct {
	dialTarget  string
	dialOptions []grpc.DialOption
	stop        func()
}

func (s *Server) NewGRPCClient(tb testing.TB, extraOptions ...grpc.DialOption) grpc.ClientConnInterface {
	dialOptions := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	dialOptions = append(dialOptions, s.dialOptions...)
	dialOptions = append(dialOptions, extraOptions...)
	conn, err := grpc.NewClient(s.dialTarget, dialOptions...)
	require.NoError(tb, err, "failed to create client")
	tb.Cleanup(func() {
		_ = conn.Close()
	})
	return conn
}

func (s *Server) Stop() {
	s.stop()
}

func StartServer(tb testing.TB, registerFn func(s grpc.ServiceRegistrar), opts ...ServerOption) *Server {
	drain := &drainHandlers{}

	var config serverConfig
	for _, opt := range opts {
		opt(&config)
	}

	// Add the drain interceptors first so that they ensure all other handlers
	// down the chain are complete before allowing the server to stop.
	unaryInterceptors := []grpc.UnaryServerInterceptor{drain.UnaryServerInterceptor}
	streamInterceptors := []grpc.StreamServerInterceptor{drain.StreamServerInterceptor}

	// Now add the context override so loggers or other things attached are
	// available to subsequent interceptors.
	if config.contextOverride != nil {
		unaryInterceptors = append(unaryInterceptors, unaryContextOverride(config.contextOverride))
		streamInterceptors = append(streamInterceptors, streamContextOverride(config.contextOverride))
	}

	// Now append the custom interceptors
	unaryInterceptors = append(unaryInterceptors, config.unaryInterceptors...)
	streamInterceptors = append(streamInterceptors, config.streamInterceptors...)

	serverOptions := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
		grpc.ChainStreamInterceptor(streamInterceptors...),
	}

	var serverListener net.Listener
	var dialTarget string
	var dialOptions []grpc.DialOption
	switch config.net {
	case "":
		listener := bufconn.Listen(1024 * 32)
		// When grpc-go deprecated grpc.DialContext() in favor of grpc.NewClient(),
		// they made a breaking change to always use the DNS resolver, even when overriding the context dialer.
		// This is problematic for tests that rely on the grpc-go bufconn transport.
		// grpc-go mentions that bufconn was only designed for internal testing of grpc-go, but we are relying on it in our tests.
		// As a workaround, use the passthrough resolver to prevent using the DNS resolver,
		// since the address is anyway being thrown away by the dialer method.
		// More context can be found in this issue: https://github.com/grpc/grpc-go/issues/1786#issuecomment-2114124036
		dialTarget = "passthrough:dummyaddressthatisignoredbybufconntransport"
		dialOptions = append(dialOptions, grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}))
		serverListener = listener
	case "unix":
		socketPath := filepath.Join(spiretest.TempDir(tb), "server.sock")
		dialTarget = "unix:" + socketPath

		listener, err := net.Listen("unix", socketPath)
		require.NoError(tb, err, "failed to open UDS listener")
		serverListener = listener
	case "tcp":
		dialTarget = config.addr

		listener, err := net.Listen("tcp", config.addr)
		require.NoError(tb, err, "failed to open TCP listener")
		serverListener = listener
	}

	// Clean up when the test is closed.
	tb.Cleanup(func() {
		_ = serverListener.Close()
	})

	server := grpc.NewServer(serverOptions...)
	registerFn(server)

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(serverListener)
	}()

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			defer func() {
				tb.Logf("Waiting for handlers to drain")
				drain.Wait()
				tb.Logf("Handlers drained")
			}()
			tb.Logf("Gracefully stopping gRPC server")
			server.GracefulStop()
			tb.Logf("Server stopped")
			err := <-errCh
			tb.Logf("Server serve returned %v", err)
			switch {
			case err == nil, errors.Is(err, grpc.ErrServerStopped):
			default:
				tb.Fatal(err)
			}
		})
	}

	// In case the test does not explicitly stop, do it on test cleanup.
	tb.Cleanup(stop)

	return &Server{
		dialTarget:  dialTarget,
		dialOptions: dialOptions,
		stop:        stop,
	}
}

type serverConfig struct {
	net                string
	addr               string
	unaryInterceptors  []grpc.UnaryServerInterceptor
	streamInterceptors []grpc.StreamServerInterceptor
	contextOverride    func(context.Context) context.Context
}

func OverUDS() ServerOption {
	return func(c *serverConfig) {
		c.net = "unix"
	}
}

func Middleware(ms ...middleware.Middleware) ServerOption {
	return func(c *serverConfig) {
		for _, m := range ms {
			unaryInterceptor, streamInterceptor := middleware.Interceptors(m)
			c.unaryInterceptors = append(c.unaryInterceptors, unaryInterceptor)
			c.streamInterceptors = append(c.streamInterceptors, streamInterceptor)
		}
	}
}

func OverrideContext(fn func(context.Context) context.Context) ServerOption {
	return func(c *serverConfig) {
		c.contextOverride = fn
	}
}

func unaryContextOverride(fn func(ctx context.Context) context.Context) func(context.Context, any, *grpc.UnaryServerInfo, grpc.UnaryHandler) (any, error) {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return handler(fn(ctx), req)
	}
}

func streamContextOverride(fn func(ctx context.Context) context.Context) func(any, grpc.ServerStream, *grpc.StreamServerInfo, grpc.StreamHandler) error {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, serverStream{
			ServerStream: ss,
			ctx:          fn(ss.Context()),
		})
	}
}

type drainHandlers struct {
	wg sync.WaitGroup
}

func (d *drainHandlers) Wait() {
	d.wg.Wait()
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

type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w serverStream) Context() context.Context {
	return w.ctx
}
