package middleware_test

import (
	"context"
)

const (
	fakeFullMethod = "/spire.api.server.foo.v1.Foo/SomeMethod"
)

type wrapKey struct{}

func wrapContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, wrapKey{}, wrapCount(ctx)+1)
}

func wrapCount(ctx context.Context) int {
	value, _ := ctx.Value(wrapKey{}).(int)
	return value
}
