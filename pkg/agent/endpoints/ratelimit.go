package endpoints

import (
	"context"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/ratelimit"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// Used to manipulate time in unit tests
	clk = clock.New()
)

type ratelimiter struct {
	metrics  telemetry.Metrics
	limiters map[string]*ratelimit.Map
}

func newRateLimiter(metrics telemetry.Metrics, limits map[string]int) *ratelimiter {
	limiters := make(map[string]*ratelimit.Map)
	for method, limit := range limits {
		if limit > 0 {
			limiters[method] = ratelimit.NewMap(limit, ratelimit.DefaultGCInterval, clk)
		}
	}

	return &ratelimiter{
		metrics:  metrics,
		limiters: limiters,
	}
}

func (r *ratelimiter) Preprocess(ctx context.Context, fullMethod string, _ any) (context.Context, error) {
	m, ok := r.limiters[fullMethod]
	if !ok {
		return ctx, nil
	}

	key := getCallerKey(ctx)
	limiter := m.Get(key)

	if !limiter.AllowN(clk.Now(), 1) {
		r.metrics.IncrCounterWithLabels([]string{telemetry.WorkloadAPI, "rate_limit_exceeded"}, 1, []telemetry.Label{
			{Name: telemetry.Method, Value: fullMethod},
			{Name: telemetry.CallerID, Value: key},
		})
		return nil, status.Errorf(codes.ResourceExhausted, "method %q rate limit exceeded for %q", fullMethod, key)
	}

	return ctx, nil
}

func withRateLimit(metrics telemetry.Metrics, limits map[string]int) middleware.Middleware {
	if len(limits) == 0 {
		return middleware.Chain()
	}
	r := newRateLimiter(metrics, limits)
	return middleware.Preprocess(r.Preprocess)
}
