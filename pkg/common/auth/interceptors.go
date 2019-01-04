package auth

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Authorizer interface {
	AuthorizeCall(ctx context.Context, fullMethod string) (context.Context, error)
}

type AuthorizerFunc func(ctx context.Context, fullMethod string) (context.Context, error)

func (fn AuthorizerFunc) AuthorizeCall(ctx context.Context, fullMethod string) (context.Context, error) {
	return fn(ctx, fullMethod)
}

func UnaryAuthorizeCall(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	ctx, err := authorizeCall(ctx, info.Server, info.FullMethod)
	if err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func StreamAuthorizeCall(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx, err := authorizeCall(ss.Context(), srv, info.FullMethod)
	if err != nil {
		return err
	}

	return handler(srv, serverStream{
		ServerStream: ss,
		ctx:          ctx,
	})
}

func authorizeCall(ctx context.Context, srv interface{}, fullMethod string) (context.Context, error) {
	authorizer, ok := srv.(Authorizer)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "server unable to provide authorization")
	}
	return authorizer.AuthorizeCall(ctx, fullMethod)
}

// used to override the context on a stream
type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s serverStream) Context() context.Context {
	return s.ctx
}
