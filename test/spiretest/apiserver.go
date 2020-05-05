package spiretest

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func NewAPIServer(t *testing.T, registerFn func(s *grpc.Server), contextFn func(ctx context.Context) context.Context) (*grpc.ClientConn, func()) {
	server := grpc.NewServer(
		grpc.UnaryInterceptor(unaryInterceptor(contextFn)),
		grpc.StreamInterceptor(streamInterceptor(contextFn)),
	)
	registerFn(server)

	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	go server.Serve(listener)

	conn, err := grpc.Dial(listener.Addr().String(), grpc.WithInsecure())
	if err != nil {
		server.Stop()
		require.NoError(t, err)
	}

	done := func() {
		assert.NoError(t, conn.Close())
		server.Stop()
	}
	return conn, done
}

func unaryInterceptor(fn func(ctx context.Context) context.Context) func(context.Context, interface{}, *grpc.UnaryServerInfo, grpc.UnaryHandler) (interface{}, error) {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		return handler(fn(ctx), req)
	}
}

func streamInterceptor(fn func(ctx context.Context) context.Context) func(interface{}, grpc.ServerStream, *grpc.StreamServerInfo, grpc.StreamHandler) error {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
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
