package catalog

import (
	"context"
	"fmt"
	"runtime/debug"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newHostServer(log logrus.FieldLogger, pluginName string, hostServices []pluginsdk.ServiceServer) *grpc.Server {
	s := grpc.NewServer(
		grpc.ChainStreamInterceptor(
			streamPanicInterceptor(log),
			streamPluginInterceptor(pluginName),
		),
		grpc.ChainUnaryInterceptor(
			unaryPanicInterceptor(log),
			unaryPluginInterceptor(pluginName),
		),
	)
	for _, hostService := range hostServices {
		hostService.RegisterServer(s)
	}
	return s
}

func streamPluginInterceptor(name string) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, streamWrapper{ctx: WithPluginName(ss.Context(), name), ServerStream: ss})
	}
}

func unaryPluginInterceptor(name string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return handler(WithPluginName(ctx, name), req)
	}
}

func streamPanicInterceptor(log logrus.FieldLogger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = convertPanic(log, r)
			}
		}()
		return handler(srv, ss)
	}
}

func unaryPanicInterceptor(log logrus.FieldLogger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (_ any, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = convertPanic(log, r)
			}
		}()
		return handler(ctx, req)
	}
}

func convertPanic(log logrus.FieldLogger, r any) error {
	log.WithFields(logrus.Fields{
		"cause": fmt.Sprint(r),
		"stack": string(debug.Stack()),
	}).Error("Plugin panicked")
	return status.Errorf(codes.Internal, "%s", r)
}

type streamWrapper struct {
	ctx context.Context
	grpc.ServerStream
}

func (w streamWrapper) Context() context.Context {
	return w.ctx
}
