package endpoints

import (
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/endpoints/workload"
	"github.com/spiffe/spire/pkg/common/ratelimit"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/telemetry/agent/workloadapi"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// perCallerRateLimiterOpts holds options for creating per-caller rate limiters.
// Exposed for testing (e.g., clock injection).
var perCallerRateLimiterOpts []ratelimit.Option

// perCallerRateLimiter wraps a ratelimit.PerKeyLimiter to provide a simple
// Allow(key) API for rate limiting by caller identity.
type perCallerRateLimiter struct {
	inner *ratelimit.PerKeyLimiter
}

func newPerCallerRateLimiter(limit int) *perCallerRateLimiter {
	return &perCallerRateLimiter{
		inner: ratelimit.NewPerKeyLimiter(func() ratelimit.Limiter {
			return rate.NewLimiter(rate.Limit(limit), limit)
		}, perCallerRateLimiterOpts...),
	}
}

// Allow reports whether 1 event may happen at the current time for the given key.
func (l *perCallerRateLimiter) Allow(key string) bool {
	limiter := l.inner.GetLimiter(key)
	return limiter.AllowN(l.inner.Now(), 1)
}

// WorkloadRateLimiter enforces per-SPIFFE-ID rate limiting on Workload API
// methods. It is called from the handler after workload attestation, once the
// caller's SPIFFE IDs are known.
type WorkloadRateLimiter struct {
	limiters map[string]*perCallerRateLimiter
	metrics  telemetry.Metrics
}

// RateLimit checks whether the request for fullMethod should be allowed given
// the caller's SPIFFE IDs. If any SPIFFE ID exceeds its rate limit, it returns
// a ResourceExhausted error.
func (r *WorkloadRateLimiter) RateLimit(fullMethod string, spiffeIDs []string) error {
	if r == nil {
		return nil
	}
	limiter, ok := r.limiters[fullMethod]
	if !ok {
		return nil
	}
	for _, id := range spiffeIDs {
		if !limiter.Allow(id) {
			workloadapi.IncrRateLimitExceededCounter(r.metrics, fullMethod)
			return status.Errorf(codes.ResourceExhausted, "rate limit exceeded for %s", fullMethod)
		}
	}
	return nil
}

// NewWorkloadRateLimiter creates a rate limiter from the given config.
// Returns nil if no limits are configured (all rates are 0).
func NewWorkloadRateLimiter(cfg WorkloadAPIRateLimitConfig, log logrus.FieldLogger, metrics telemetry.Metrics) *WorkloadRateLimiter {
	type methodLimit struct {
		method string
		limit  int
	}

	methods := []methodLimit{
		{workload.MethodFetchX509SVID, cfg.FetchX509SVID},
		{workload.MethodFetchJWTSVID, cfg.FetchJWTSVID},
	}

	limiters := make(map[string]*perCallerRateLimiter)
	for _, ml := range methods {
		if ml.limit > 0 {
			limiters[ml.method] = newPerCallerRateLimiter(ml.limit)
			log.WithFields(logrus.Fields{
				telemetry.Method: ml.method,
				telemetry.Limit:  ml.limit,
			}).Info("Workload API rate limiting enabled")
		}
	}

	if len(limiters) == 0 {
		return nil
	}

	return &WorkloadRateLimiter{
		limiters: limiters,
		metrics:  metrics,
	}
}
