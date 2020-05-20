package middleware_test

import (
	"context"
	"errors"
	"testing"

	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

var (
	fakeUnaryServerInfo  = &grpc.UnaryServerInfo{FullMethod: fakeMethodName}
	fakeStreamServerInfo = &grpc.StreamServerInfo{FullMethod: fakeMethodName}
)

func TestInterceptors(t *testing.T) {
	t.Run("unary", func(t *testing.T) {
		testUnaryInterceptor(t, func(m middleware.Middleware) grpc.UnaryServerInterceptor {
			unary, _ := middleware.Interceptors(m)
			return unary
		})
	})
	t.Run("stream", func(t *testing.T) {
		testStreamInterceptor(t, func(m middleware.Middleware) grpc.StreamServerInterceptor {
			_, stream := middleware.Interceptors(m)
			return stream
		})
	})
}

func TestUnaryInterceptor(t *testing.T) {
	testUnaryInterceptor(t, middleware.UnaryInterceptor)
}

func TestStreamInterceptor(t *testing.T) {
	testStreamInterceptor(t, middleware.StreamInterceptor)
}

func testUnaryInterceptor(t *testing.T, makeInterceptor func(m middleware.Middleware) grpc.UnaryServerInterceptor) {
	t.Run("success", func(t *testing.T) {
		m := new(fakeMiddleware)
		unary := makeInterceptor(m)
		resp, err := unary(context.Background(), "request", fakeUnaryServerInfo,
			func(ctx context.Context, req interface{}) (interface{}, error) {
				// Assert that parameters were threaded correctly through
				// the interceptor.
				assert.Equal(t, 1, wrapCount(ctx))
				assert.Equal(t, "request", req)
				return "response", nil
			},
		)

		// Assert that:
		// 1) Interceptor returned the response and no error
		// 2) Preprocess was called
		// 3) Postprocess was called with "handlerInvoked" and no error
		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
		assert.Equal(t, preprocessArgs{wrapCount: 0, methodName: fakeMethodName}, m.lastPreprocess)
		assert.Equal(t, postprocessArgs{wrapCount: 1, methodName: fakeMethodName, handlerInvoked: true, rpcErr: nil}, m.lastPostprocess)
	})

	t.Run("preprocess failure", func(t *testing.T) {
		m := new(fakeMiddleware)
		m.nextPreprocessErr = errFake

		unary := makeInterceptor(m)
		resp, err := unary(context.Background(), "request", fakeUnaryServerInfo,
			func(ctx context.Context, req interface{}) (interface{}, error) {
				// Since preprocess fails, the handler should not be invoked.
				require.FailNow(t, "handler should not have been called")
				return nil, errors.New("unreachable")
			},
		)

		// Assert that:
		// 1) Interceptor returned the preprocess failure
		// 2) Preprocess was called
		// 3) Postprocess was not called
		assert.Equal(t, errFake, err)
		assert.Nil(t, resp)
		assert.Equal(t, preprocessArgs{wrapCount: 0, methodName: fakeMethodName}, m.lastPreprocess)
		assert.Equal(t, postprocessArgs{}, m.lastPostprocess)
	})

	t.Run("handler failure", func(t *testing.T) {
		m := new(fakeMiddleware)

		unary := makeInterceptor(m)
		resp, err := unary(context.Background(), "request", fakeUnaryServerInfo,
			func(ctx context.Context, req interface{}) (interface{}, error) {
				// Assert that parameters were threaded correctly through
				// the interceptor.
				assert.Equal(t, 1, wrapCount(ctx))
				assert.Equal(t, "request", req)
				return nil, errFake
			},
		)

		// Assert that:
		// 1) Interceptor returned the handler failure
		// 2) Preprocess was called
		// 3) Postprocess was called with "handlerInvoked" and the handler error
		assert.Equal(t, err, errFake)
		assert.Nil(t, resp)
		assert.Equal(t, preprocessArgs{wrapCount: 0, methodName: fakeMethodName}, m.lastPreprocess)
		assert.Equal(t, postprocessArgs{wrapCount: 1, methodName: fakeMethodName, handlerInvoked: true, rpcErr: errFake}, m.lastPostprocess)
	})
}

func testStreamInterceptor(t *testing.T, makeInterceptor func(m middleware.Middleware) grpc.StreamServerInterceptor) {
	t.Run("success", func(t *testing.T) {
		m := new(fakeMiddleware)

		stream := makeInterceptor(m)
		err := stream("server", fakeServerStream{}, fakeStreamServerInfo,
			func(srv interface{}, stream grpc.ServerStream) error {
				// Assert that parameters were threaded correctly through
				// the interceptor.
				assert.Equal(t, "server", srv)
				assert.Equal(t, 1, wrapCount(stream.Context()))
				return nil
			},
		)

		// Assert that:
		// 1) Interceptor returned no error
		// 2) Preprocess was called
		// 3) Postprocess was called with "handlerInvoked" and no error
		assert.NoError(t, err)
		assert.Equal(t, preprocessArgs{wrapCount: 0, methodName: fakeMethodName}, m.lastPreprocess)
		assert.Equal(t, postprocessArgs{wrapCount: 1, methodName: fakeMethodName, handlerInvoked: true, rpcErr: nil}, m.lastPostprocess)
	})

	t.Run("preprocess failure", func(t *testing.T) {
		m := new(fakeMiddleware)
		m.nextPreprocessErr = errFake

		stream := makeInterceptor(m)
		err := stream("server", fakeServerStream{}, fakeStreamServerInfo,
			func(srv interface{}, stream grpc.ServerStream) error {
				// Since preprocess fails, the handler should not be invoked.
				require.FailNow(t, "handler should not have been called")
				return errors.New("unreachable")
			},
		)

		// Assert that:
		// 1) Interceptor returned the preprocess failure
		// 2) Preprocess was called
		// 3) Postprocess was not called
		assert.Equal(t, errFake, err)
		assert.Equal(t, preprocessArgs{wrapCount: 0, methodName: fakeMethodName}, m.lastPreprocess)
		assert.Equal(t, postprocessArgs{}, m.lastPostprocess)
	})

	t.Run("handler failure", func(t *testing.T) {
		m := new(fakeMiddleware)

		stream := makeInterceptor(m)
		err := stream("server", fakeServerStream{}, fakeStreamServerInfo,
			func(srv interface{}, stream grpc.ServerStream) error {
				// Assert that parameters were threaded correctly through
				// the interceptor.
				assert.Equal(t, "server", srv)
				assert.Equal(t, 1, wrapCount(stream.Context()))
				return errFake
			},
		)

		// Assert that:
		// 1) Interceptor returned the handler failure
		// 2) Preprocess was called
		// 3) Postprocess was called with "handlerInvoked" and the handler error
		assert.Equal(t, err, errFake)
		assert.Equal(t, preprocessArgs{wrapCount: 0, methodName: fakeMethodName}, m.lastPreprocess)
		assert.Equal(t, postprocessArgs{wrapCount: 1, methodName: fakeMethodName, handlerInvoked: true, rpcErr: errFake}, m.lastPostprocess)
	})
}

type fakeServerStream struct {
	grpc.ServerStream
}

func (ss fakeServerStream) Context() context.Context {
	return context.Background()
}
