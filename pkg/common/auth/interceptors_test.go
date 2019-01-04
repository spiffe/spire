package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestUnaryAuthorizeCall(t *testing.T) {
	// server does not implement the Authorizer interface
	resp, err := UnaryAuthorizeCall(context.Background(), nil, &grpc.UnaryServerInfo{
		Server:     nil,
		FullMethod: "FOO",
	}, nil)
	require.EqualError(t, err, "rpc error: code = PermissionDenied desc = server unable to provide authorization")
	require.Nil(t, resp)

	// authorizer fails authorization
	server := AuthorizerFunc(func(context.Context, string) (context.Context, error) {
		return nil, errors.New("no auth for you")
	})
	resp, err = UnaryAuthorizeCall(context.Background(), nil, &grpc.UnaryServerInfo{
		Server:     server,
		FullMethod: "FOO",
	}, nil)
	require.EqualError(t, err, "no auth for you")
	require.Nil(t, resp)

	// success
	server = AuthorizerFunc(func(ctx context.Context, fullMethod string) (context.Context, error) {
		require.Equal(t, "FOO", fullMethod)
		return context.WithValue(ctx, "key", "value"), nil
	})
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		require.Equal(t, "value", ctx.Value("key"))
		require.Equal(t, "req", req)
		return "resp", errors.New("error")
	}
	resp, err = UnaryAuthorizeCall(context.Background(), "req", &grpc.UnaryServerInfo{
		Server:     server,
		FullMethod: "FOO",
	}, handler)
	require.EqualError(t, err, "error")
	require.Equal(t, "resp", resp)
}

func TestStreamAuthorizeCall(t *testing.T) {
	stream := serverStream{ctx: context.Background()}
	info := &grpc.StreamServerInfo{FullMethod: "FOO"}

	// server does not implement the Authorizer interface
	err := StreamAuthorizeCall(nil, stream, info, nil)
	require.EqualError(t, err, "rpc error: code = PermissionDenied desc = server unable to provide authorization")

	// authorizer fails authorization
	server := AuthorizerFunc(func(ctx context.Context, fullMethod string) (context.Context, error) {
		return nil, errors.New("no auth for you")
	})
	err = StreamAuthorizeCall(server, stream, info, nil)
	require.EqualError(t, err, "no auth for you")

	// success
	server = AuthorizerFunc(func(ctx context.Context, fullMethod string) (context.Context, error) {
		require.Equal(t, "FOO", fullMethod)
		return context.WithValue(ctx, "key", "value"), nil
	})
	handler := func(server interface{}, stream grpc.ServerStream) error {
		require.NotNil(t, server)
		require.Equal(t, "value", stream.Context().Value("key"))
		return errors.New("error")
	}
	err = StreamAuthorizeCall(server, stream, info, handler)
	require.EqualError(t, err, "error")
}
