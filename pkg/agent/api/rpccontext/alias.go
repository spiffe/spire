package rpccontext

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/api"
	"github.com/spiffe/spire/pkg/common/api/rpccontext"
)

func WithLogger(ctx context.Context, log logrus.FieldLogger) context.Context {
	return rpccontext.WithLogger(ctx, log)
}

func Logger(ctx context.Context) logrus.FieldLogger {
	return rpccontext.Logger(ctx)
}

func WithCallCounter(ctx context.Context, counter api.CallCounter) context.Context {
	return rpccontext.WithCallCounter(ctx, counter)
}

func CallCounter(ctx context.Context) api.CallCounter {
	return rpccontext.CallCounter(ctx)
}

func AddMetricsLabel(ctx context.Context, name, value string) {
	CallCounter(ctx).AddLabel(name, value)
}

func WithNames(ctx context.Context, names api.Names) context.Context {
	return rpccontext.WithNames(ctx, names)
}

func Names(ctx context.Context) (api.Names, bool) {
	return rpccontext.Names(ctx)
}
