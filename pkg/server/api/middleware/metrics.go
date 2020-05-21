package middleware

import (
	"context"

	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
)

// WithMetrics adds per-call metrics to each RPC call. It emits both a call
// counter and sample with the call timing. RPC handlers can add their own
// labels to be attached to the per-call metrics via the
// rpccontext.AddMetricsLabel function. If unset, it also provides name
// metadata on to the handler context.
func WithMetrics(metrics telemetry.Metrics) Middleware {
	return metricsMiddleware{
		metrics: metrics,
	}
}

type metricsMiddleware struct {
	metrics telemetry.Metrics
}

func (m metricsMiddleware) Preprocess(ctx context.Context, fullMethod string) (context.Context, error) {
	ctx, names := withNames(ctx, fullMethod)
	counter := telemetry.StartCall(m.metrics, names.Service, names.Method)
	return rpccontext.WithCallCounter(ctx, counter), nil
}

func (m metricsMiddleware) Postprocess(ctx context.Context, fullMethod string, handlerInvoked bool, rpcErr error) {
	counter, ok := rpccontext.CallCounter(ctx).(*telemetry.CallCounter)
	if !ok {
		rpccontext.Logger(ctx).WithField("method", fullMethod).Error("Metrics misconfigured; this is a bug")
		return
	}
	counter.Done(&rpcErr)
}
