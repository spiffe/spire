package spiretest

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func NewAPIServerWithMiddleware(tb testing.TB, registerFn func(s *grpc.Server), server *grpc.Server) (*grpc.ClientConn, func()) {
	return newAPIServer(tb, registerFn, server)
}

func NewAPIServer(tb testing.TB, registerFn func(s *grpc.Server), contextFn func(ctx context.Context) context.Context) (*grpc.ClientConn, func()) {
	server := grpc.NewServer(
		grpc.UnaryInterceptor(unaryInterceptor(contextFn)),
		grpc.StreamInterceptor(streamInterceptor(contextFn)),
	)
	return newAPIServer(tb, registerFn, server)
}

func newAPIServer(tb testing.TB, registerFn func(s *grpc.Server), server *grpc.Server) (*grpc.ClientConn, func()) {
	registerFn(server)

	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(tb, err)

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()

	conn, err := grpc.Dial(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		server.Stop()
		require.NoError(tb, err)
	}

	done := func() {
		assert.NoError(tb, conn.Close())
		server.GracefulStop()
		err := <-errCh
		switch {
		case err == nil, errors.Is(err, grpc.ErrServerStopped):
		default:
			tb.Fatal(err)
		}
	}
	return conn, done
}

type DrainHandlerMiddleware struct {
	wg sync.WaitGroup
}

func NewDrainHandlerMiddleware() *DrainHandlerMiddleware {
	return &DrainHandlerMiddleware{}
}

func (m *DrainHandlerMiddleware) Wait() {
	m.wg.Wait()
}

func (m *DrainHandlerMiddleware) Preprocess(ctx context.Context, _ string, _ any) (context.Context, error) {
	m.wg.Add(1)
	return ctx, nil
}

func (m *DrainHandlerMiddleware) Postprocess(context.Context, string, bool, error) {
	m.wg.Done()
}

func (m *DrainHandlerMiddleware) UnaryServerInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	m.wg.Add(1)
	defer m.wg.Done()
	return handler(ctx, req)
}

func (m *DrainHandlerMiddleware) StreamServerInterceptor(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	m.wg.Add(1)
	defer m.wg.Done()
	return handler(srv, ss)
}

func unaryInterceptor(fn func(ctx context.Context) context.Context) func(context.Context, any, *grpc.UnaryServerInfo, grpc.UnaryHandler) (any, error) {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return handler(fn(ctx), req)
	}
}

func streamInterceptor(fn func(ctx context.Context) context.Context) func(any, grpc.ServerStream, *grpc.StreamServerInfo, grpc.StreamHandler) error {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, serverStream{
			ServerStream: ss,
			ctx:          fn(ss.Context()),
		})
	}
}

type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w serverStream) Context() context.Context {
	return w.ctx
}
