package middleware

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/api/rpccontext"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// WithLogger returns logging middleware that provides a per-rpc logger with
// some initial fields set. If unset, it also provides name metadata to the
// handler context.
func WithLogger(log logrus.FieldLogger) Middleware {
	return Preprocess(func(ctx context.Context, fullMethod string, req interface{}) (context.Context, error) {
		ctx, names := withNames(ctx, fullMethod)
		log := log.WithFields(logrus.Fields{
			telemetry.Service: names.Service,
			telemetry.Method:  names.Method,
		})
		return rpccontext.WithLogger(ctx, log), nil
	})
}
