package middleware

import (
	"context"

	"google.golang.org/grpc"
)

type PreprocessFunc = func(ctx context.Context, methodName string) (context.Context, error)
type PostprocessFunc = func(ctx context.Context, methodName string, handlerInvoked bool, rpcErr error)

type Middleware interface {
	// Preprocess is invoked before the gRPC handler is called. It returns a
	// (possibly modified) context that is passed into the handler. The context
	// should either be the context passed into the function or one derived
	// from it. If the function returns an error, the gRPC method fails.
	Preprocess(ctx context.Context, methodName string) (context.Context, error)

	// Postprocess is invoked after the handler is called, or if downstream
	// middleware returns an error from Preprocess. The function is passed an
	// error that was returned from the handler or a downstream middleware
	// during preprocessing. The handlerInvoked boolean, if true, indicates
	// that the handler was executed. If false, then the call failed during
	// preprocessing.
	Postprocess(ctx context.Context, methodName string, handlerInvoked bool, rpcErr error)
}

func Preprocess(fn PreprocessFunc) Middleware {
	return funcs{
		preprocess: fn,
	}
}

func Postprocess(fn PostprocessFunc) Middleware {
	return funcs{
		postprocess: fn,
	}
}

// Funcs constructs a Middleware from a pair of functions, one for preprocessing, one for postprocessing.
func Funcs(preprocess PreprocessFunc, postprocess PostprocessFunc) Middleware {
	return funcs{
		preprocess:  preprocess,
		postprocess: postprocess,
	}
}

func Chain(middleware ...Middleware) Middleware {
	return middlewares(middleware)
}

type funcs struct {
	preprocess  PreprocessFunc
	postprocess PostprocessFunc
}

// Preprocess implements the Middleware interface
func (h funcs) Preprocess(ctx context.Context, methodName string) (context.Context, error) {
	if h.preprocess != nil {
		return h.preprocess(ctx, methodName)
	}
	return ctx, nil
}

// Preprocess implements the Middleware interface
func (h funcs) Postprocess(ctx context.Context, methodName string, handlerInvoked bool, rpcErr error) {
	if h.postprocess != nil {
		h.postprocess(ctx, methodName, handlerInvoked, rpcErr)
	}
}

type middlewares []Middleware

func (ms middlewares) Preprocess(ctx context.Context, methodName string) (context.Context, error) {
	if len(ms) == 0 {
		return ctx, nil
	}

	m := ms[0]
	ms = ms[1:]

	ctx, err := m.Preprocess(ctx, methodName)
	if err != nil {
		return nil, err
	}

	downstreamCtx, err := ms.Preprocess(ctx, methodName)
	if err != nil {
		// The downstream middleware failed to preprocess. Invoke the
		// postprocess step of this middleware layer, passing in the context
		// originally set up by this layer.
		m.Postprocess(ctx, methodName, false, err)
		return nil, err
	}

	return downstreamCtx, nil
}

func (ms middlewares) Postprocess(ctx context.Context, methodName string, handlerInvoked bool, rpcErr error) {
	for i := len(ms) - 1; i >= 0; i-- {
		ms[i].Postprocess(ctx, methodName, handlerInvoked, rpcErr)
	}
}

type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (ss serverStream) Context() context.Context {
	return ss.ctx
}
