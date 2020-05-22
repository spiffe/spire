package middleware_test

import (
	"context"
	"testing"

	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/stretchr/testify/assert"
)

func TestChain(t *testing.T) {
	var preprocessCalls []string
	var postprocessCalls []string

	// wrap wraps the middleware to facilitate determining which middleware
	// was called and in what order.
	wrap := func(id string, m middleware.Middleware) middleware.Middleware {
		return middleware.Funcs(
			func(ctx context.Context, fullMethod string) (context.Context, error) {
				preprocessCalls = append(preprocessCalls, id)
				return m.Preprocess(ctx, fullMethod)
			},
			func(ctx context.Context, fullMethod string, handlerInvoked bool, rpcErr error) {
				postprocessCalls = append(postprocessCalls, id)
				m.Postprocess(ctx, fullMethod, handlerInvoked, rpcErr)
			},
		)
	}

	setup := func() (chain middleware.Middleware, a, b, c, d *fakeMiddleware) {
		// reset ordering
		preprocessCalls = nil
		postprocessCalls = nil

		a = new(fakeMiddleware)
		b = new(fakeMiddleware)
		c = new(fakeMiddleware)
		d = new(fakeMiddleware)
		chain = middleware.Chain(wrap("a", a), wrap("b", b), wrap("c", c), wrap("d", d))
		return chain, a, b, c, d
	}

	t.Run("preprocess ok", func(t *testing.T) {
		chain, a, b, c, d := setup()

		// Preprocess and assert the wrap count for the returned context
		ctx, err := chain.Preprocess(context.Background(), fakeFullMethod)
		assert.NoError(t, err)
		assert.Equal(t, 4, wrapCount(ctx))

		// Assert the preprocess call order and the wrap count at each invocation
		assert.Equal(t, []string{"a", "b", "c", "d"}, preprocessCalls)
		assert.Equal(t, preprocessArgs{wrapCount: 0, fullMethod: fakeFullMethod}, a.lastPreprocess)
		assert.Equal(t, preprocessArgs{wrapCount: 1, fullMethod: fakeFullMethod}, b.lastPreprocess)
		assert.Equal(t, preprocessArgs{wrapCount: 2, fullMethod: fakeFullMethod}, c.lastPreprocess)
		assert.Equal(t, preprocessArgs{wrapCount: 3, fullMethod: fakeFullMethod}, d.lastPreprocess)

		// Assert that postprocess wasn't called because no failures happened
		assert.Nil(t, postprocessCalls)
	})

	t.Run("preprocess fails", func(t *testing.T) {
		chain, a, b, c, d := setup()

		// Fail preprocessing and assert the error is returned
		c.nextPreprocessErr = errFake
		ctx, err := chain.Preprocess(context.Background(), fakeFullMethod)
		assert.Equal(t, errFake, err)
		assert.Nil(t, ctx)

		// Assert the preprocess call order and the wrap count at each invocation
		assert.Equal(t, []string{"a", "b", "c"}, preprocessCalls)
		assert.Equal(t, preprocessArgs{wrapCount: 0, fullMethod: fakeFullMethod}, a.lastPreprocess)
		assert.Equal(t, preprocessArgs{wrapCount: 1, fullMethod: fakeFullMethod}, b.lastPreprocess)
		assert.Equal(t, preprocessArgs{wrapCount: 2, fullMethod: fakeFullMethod}, c.lastPreprocess)
		assert.Equal(t, preprocessArgs{}, d.lastPreprocess)

		// Assert that postprocess was called for the middleware that
		// preprocessed. The calls should be in reverse order.
		assert.Equal(t, []string{"b", "a"}, postprocessCalls)
		assert.Equal(t, postprocessArgs{wrapCount: 1, fullMethod: fakeFullMethod, handlerInvoked: false, rpcErr: errFake}, a.lastPostprocess)
		assert.Equal(t, postprocessArgs{wrapCount: 2, fullMethod: fakeFullMethod, handlerInvoked: false, rpcErr: errFake}, b.lastPostprocess)
		assert.Equal(t, postprocessArgs{}, c.lastPostprocess)
		assert.Equal(t, postprocessArgs{}, d.lastPostprocess)
	})

	t.Run("postprocess runs in order", func(t *testing.T) {
		chain, _, _, _, _ := setup()

		chain.Postprocess(context.Background(), fakeFullMethod, false, nil)

		assert.Equal(t, []string{"d", "c", "b", "a"}, postprocessCalls)
	})
}

func TestPreprocess(t *testing.T) {
	t.Run("via Preprocess", func(t *testing.T) {
		f := new(fakeMiddleware)
		testPreprocess(t, f, middleware.Preprocess(f.Preprocess))
	})

	t.Run("via Funcs", func(t *testing.T) {
		f := new(fakeMiddleware)
		testPreprocess(t, f, middleware.Funcs(f.Preprocess, nil))
	})
}

func TestPostprocess(t *testing.T) {
	t.Run("via Postprocess", func(t *testing.T) {
		f := new(fakeMiddleware)
		testPostprocess(t, f, middleware.Postprocess(f.Postprocess))
	})

	t.Run("via Funcs", func(t *testing.T) {
		f := new(fakeMiddleware)
		testPostprocess(t, f, middleware.Funcs(nil, f.Postprocess))
	})
}

func testPreprocess(t *testing.T, f *fakeMiddleware, m middleware.Middleware) {
	// Assert that the wrapped context is returned from the callback.
	ctx, err := m.Preprocess(context.Background(), "FIRST")
	assert.NoError(t, err)
	assert.Equal(t, 1, wrapCount(ctx))

	assert.Equal(t, preprocessArgs{wrapCount: 0, fullMethod: "FIRST"}, f.lastPreprocess)

	// Assert that errors are returned from the callback.
	f.nextPreprocessErr = errFake
	ctx, err = m.Preprocess(context.Background(), "SECOND")
	assert.Equal(t, errFake, err)
	assert.Nil(t, ctx)

	assert.Equal(t, preprocessArgs{wrapCount: 0, fullMethod: "SECOND"}, f.lastPreprocess)

	// Assert that postprocess is a noop. There isn't really a good way so
	// let's just make sure it doesn't panic or something.
	assert.NotPanics(t, func() {
		m.Postprocess(context.Background(), fakeFullMethod, false, nil)
	})
}

func testPostprocess(t *testing.T, f *fakeMiddleware, m middleware.Middleware) {
	// Assert that the parameters are passed through correctly
	ctx := wrapContext(context.Background())
	m.Postprocess(ctx, "FIRST", false, nil)
	assert.Equal(t, postprocessArgs{wrapCount: 1, fullMethod: "FIRST", handlerInvoked: false, rpcErr: nil}, f.lastPostprocess)

	ctx = wrapContext(ctx)
	m.Postprocess(ctx, "SECOND", true, errFake)
	assert.Equal(t, postprocessArgs{wrapCount: 2, fullMethod: "SECOND", handlerInvoked: true, rpcErr: errFake}, f.lastPostprocess)

	// Assert that Preprocess returns the passed in context
	ctx = wrapContext(ctx)
	ctx, err := m.Preprocess(ctx, fakeFullMethod)
	assert.NoError(t, err, nil)
	assert.Equal(t, 3, wrapCount(ctx))
}
