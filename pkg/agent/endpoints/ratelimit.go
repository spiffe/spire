package endpoints

import (
	"slices"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/endpoints/sdsv3"
	"github.com/spiffe/spire/pkg/agent/endpoints/workload"
	"github.com/spiffe/spire/pkg/common/ratelimit"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/telemetry/agent/workloadapi"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/common"
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

// selectorSetKey builds a collision-resistant string key from a selector set.
// Selectors are sorted for stability, then joined with two distinct separators
// ('\x00' between type/value, '\x01' between pairs). Empty input returns "<unattested>".
func selectorSetKey(selectors []*common.Selector) string {
	if len(selectors) == 0 {
		return "<unattested>"
	}
	sorted := slices.Clone(selectors)
	util.SortSelectors(sorted)
	var b strings.Builder
	for i, s := range sorted {
		if i > 0 {
			b.WriteByte('\x01')
		}
		b.WriteString(s.Type)
		b.WriteByte('\x00')
		b.WriteString(s.Value)
	}
	return b.String()
}

// WorkloadRateLimiter enforces per-selector-set rate limiting on Workload API
// methods. It is called from the handler after workload attestation, once the
// caller's attested selectors are known.
type WorkloadRateLimiter struct {
	limiters map[string]*perCallerRateLimiter
	metrics  telemetry.Metrics
}

// RateLimit checks whether the request for fullMethod should be allowed given
// the caller's attested selectors. The selector set is treated as a single key,
// so all workloads with the same selector set share one token bucket. Callers
// with no selectors share an "<unattested>" bucket. Methods without a
// configured limit pass through.
func (r *WorkloadRateLimiter) RateLimit(fullMethod string, selectors []*common.Selector) error {
	limiter, ok := r.limiters[fullMethod]
	if !ok {
		return nil
	}
	key := selectorSetKey(selectors)
	if !limiter.Allow(key) {
		workloadapi.IncrRateLimitExceededCounter(r.metrics, fullMethod)
		return status.Errorf(codes.Unavailable, "rate limit exceeded for %s", fullMethod)
	}
	return nil
}

// NewWorkloadRateLimiter creates a rate limiter from the given config. Methods
// with a zero limit are omitted from the limiters map and pass through at
// RateLimit time; if no methods are configured the result is effectively a
// no-op for every call.
func NewWorkloadRateLimiter(cfg WorkloadAPIRateLimitConfig, log logrus.FieldLogger, metrics telemetry.Metrics) *WorkloadRateLimiter {
	type methodLimit struct {
		method string
		limit  int
	}

	methods := []methodLimit{
		{workload.MethodFetchX509SVID, cfg.FetchX509SVID},
		{workload.MethodFetchJWTSVID, cfg.FetchJWTSVID},
		{workload.MethodFetchX509Bundles, cfg.FetchX509Bundles},
		{workload.MethodFetchJWTBundles, cfg.FetchJWTBundles},
		{sdsv3.MethodStreamSecrets, cfg.StreamSecrets},
		{sdsv3.MethodFetchSecrets, cfg.FetchSecrets},
	}

	limiters := make(map[string]*perCallerRateLimiter)
	for _, ml := range methods {
		if ml.limit > 0 {
			limiters[ml.method] = newPerCallerRateLimiter(ml.limit)
			log.WithFields(logrus.Fields{
				telemetry.Method: ml.method,
				telemetry.Limit:  ml.limit,
			}).Info("Workload API/SDS rate limiting enabled")
		}
	}

	return &WorkloadRateLimiter{
		limiters: limiters,
		metrics:  metrics,
	}
}
