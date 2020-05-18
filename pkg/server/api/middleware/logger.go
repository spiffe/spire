package middleware

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
)

func WithLogger(log logrus.FieldLogger) Middleware {
	return Preprocess(func(ctx context.Context, methodName string) (context.Context, error) {
		return rpccontext.WithLogger(ctx, log), nil
	})
}
