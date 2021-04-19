package catalog

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newHostServer(pluginName string, hostServices []HostServiceServer) *grpc.Server {
	s := grpc.NewServer(
		grpc.ChainStreamInterceptor(
			streamPanicInterceptor,
			streamPluginInterceptor(pluginName),
		),
		grpc.ChainUnaryInterceptor(
			unaryPanicInterceptor,
			unaryPluginInterceptor(pluginName),
		),
	)
	for _, hostService := range hostServices {
		hostService.ServiceServer.RegisterServer(s)
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

func streamPanicInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = status.Errorf(codes.Internal, "%s", r)
		}
	}()
	return handler(srv, ss)
}

func unaryPanicInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (_ interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = status.Errorf(codes.Internal, "%s", r)
		}
	}()
	return handler(ctx, req)
}

type streamWrapper struct {
	ctx context.Context
	grpc.ServerStream
}

func (w streamWrapper) Context() context.Context {
	return w.ctx
}
