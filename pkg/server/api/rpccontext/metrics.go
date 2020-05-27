package rpccontext

import (
	"context"

	"github.com/spiffe/spire/pkg/server/api"
)

type callCounterKey struct{}

func WithCallCounter(ctx context.Context, counter api.CallCounter) context.Context {
	return context.WithValue(ctx, callCounterKey{}, counter)
}

func CallCounter(ctx context.Context) api.CallCounter {
	return ctx.Value(callCounterKey{}).(api.CallCounter)
}

func AddMetricsLabel(ctx context.Context, name, value string) {
	CallCounter(ctx).AddLabel(name, value)
}
