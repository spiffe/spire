package catalog

import (
	"context"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/spiffe/spire/pkg/common/catalog/interfaces"
	"google.golang.org/grpc"
)

func PluginNameFromHostServiceContext(ctx context.Context) (string, bool) {
	return interfaces.PluginNameFromHostServiceContext(ctx)
}

func WithPluginName(ctx context.Context, name string) context.Context {
	return interfaces.WithPluginName(ctx, name)
}

func NewHostServer(pluginName string, opts []grpc.ServerOption, hostServices []HostServiceServer) *grpc.Server {
	s := grpc.NewServer(append(opts,
		grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(
			streamPluginInterceptor(pluginName),
			grpc_recovery.StreamServerInterceptor(),
		)),
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			unaryPluginInterceptor(pluginName),
			grpc_recovery.UnaryServerInterceptor(),
		)),
	)...)
	for _, hostService := range hostServices {
		hostService.RegisterHostServiceServer(s)
	}
	return s
}

func streamPluginInterceptor(name string) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, streamWrapper{ctx: WithPluginName(ss.Context(), name), ServerStream: ss})
	}
}

func unaryPluginInterceptor(name string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		return handler(WithPluginName(ctx, name), req)
	}
}

type streamWrapper struct {
	ctx context.Context
	grpc.ServerStream
}

func (w streamWrapper) Context() context.Context {
	return w.ctx
}
