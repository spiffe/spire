package middleware

import (
	"context"

	"github.com/spiffe/spire/pkg/common/api/rpccontext"
	"github.com/spiffe/spire/pkg/common/telemetry"
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

func (m metricsMiddleware) Preprocess(ctx context.Context, fullMethod string, _ any) (context.Context, error) {
	ctx, names := withNames(ctx, fullMethod)
	counter := telemetry.StartCall(m.metrics, "rpc", names.MetricKey...)
	return rpccontext.WithCallCounter(ctx, counter), nil
}

func (m metricsMiddleware) Postprocess(ctx context.Context, _ string, _ bool, rpcErr error) {
	counter, ok := rpccontext.CallCounter(ctx).(*telemetry.CallCounter)
	if !ok {
		LogMisconfiguration(ctx, "Metrics misconfigured; this is a bug")
		return
	}
	counter.Done(&rpcErr)
}
