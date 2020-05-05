package rpccontext

import (
	"context"

	"github.com/sirupsen/logrus"
)

type loggerKey struct{}

func WithLogger(ctx context.Context, log logrus.FieldLogger) context.Context {
	return context.WithValue(ctx, loggerKey{}, log)
}

func Logger(ctx context.Context) logrus.FieldLogger {
	log, ok := ctx.Value(loggerKey{}).(logrus.FieldLogger)
	if ok {
		return log
	}
	panic("RPC context missing logger")
}
