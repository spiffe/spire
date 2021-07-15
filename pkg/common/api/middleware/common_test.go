package middleware_test

import (
	"context"
	"errors"
)

const (
	fakeFullMethod = "/spire.api.server.foo.v1.Foo/SomeMethod"
)

var (
	errFake = errors.New("ohno")
)

type preprocessArgs struct {
	wrapCount  int
	req        interface{}
	fullMethod string
}

type postprocessArgs struct {
	wrapCount      int
	fullMethod     string
	handlerInvoked bool
	rpcErr         error
}

type fakeMiddleware struct {
	lastPreprocess    preprocessArgs
	lastPostprocess   postprocessArgs
	nextPreprocessErr error
}

func (f *fakeMiddleware) Preprocess(ctx context.Context, fullMethod string, req interface{}) (context.Context, error) {
	f.lastPreprocess = preprocessArgs{
		wrapCount:  wrapCount(ctx),
		req:        req,
		fullMethod: fullMethod,
	}
	if err := f.nextPreprocessErr; err != nil {
		f.nextPreprocessErr = nil
		return nil, err
	}
	return wrapContext(ctx), nil
}

func (f *fakeMiddleware) Postprocess(ctx context.Context, fullMethod string, handlerInvoked bool, rpcErr error) {
	f.lastPostprocess = postprocessArgs{
		wrapCount:      wrapCount(ctx),
		fullMethod:     fullMethod,
		handlerInvoked: handlerInvoked,
		rpcErr:         rpcErr,
	}
}

type wrapKey struct{}

func wrapContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, wrapKey{}, wrapCount(ctx)+1)
}

func wrapCount(ctx context.Context) int {
	value, _ := ctx.Value(wrapKey{}).(int)
	return value
}
