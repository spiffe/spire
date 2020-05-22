package rpccontext

import (
	"context"

	"github.com/spiffe/spire/pkg/server/api"
)

type namesKey struct{}

func WithNames(ctx context.Context, names api.Names) context.Context {
	return context.WithValue(ctx, namesKey{}, names)
}

func Names(ctx context.Context) (api.Names, bool) {
	value, ok := ctx.Value(namesKey{}).(api.Names)
	return value, ok
}
