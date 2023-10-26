package middleware

import (
	"context"

	"google.golang.org/grpc"
)

func Interceptors(middleware Middleware) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	return UnaryInterceptor(middleware), StreamInterceptor(middleware)
}

func UnaryInterceptor(middleware Middleware) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, err := middleware.Preprocess(ctx, info.FullMethod, req)
		if err != nil {
			return nil, err
		}
		resp, err := handler(ctx, req)
		middleware.Postprocess(ctx, info.FullMethod, true, err)
		return resp, err
	}
}

func StreamInterceptor(middleware Middleware) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := middleware.Preprocess(ss.Context(), info.FullMethod, nil)
		if err != nil {
			return err
		}
		err = handler(srv, serverStream{ServerStream: ss, ctx: ctx})
		middleware.Postprocess(ctx, info.FullMethod, true, err)
		return err
	}
}

type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (ss serverStream) Context() context.Context {
	return ss.ctx
}
