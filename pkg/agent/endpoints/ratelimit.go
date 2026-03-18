package endpoints

import (
	"context"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/ratelimit"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/telemetry/agent/workloadapi"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	podKeyPrefix = "pod:"
	uidKeyPrefix = "uid:"
)

// perCallerRateLimiterOpts holds options for creating per-caller rate limiters.
// Exposed for testing (e.g., clock injection).
var perCallerRateLimiterOpts []ratelimit.Option

// podUIDResolver extracts a Kubernetes pod UID for the given process, returning
// an empty string if unavailable (e.g., not running in Kubernetes).
type podUIDResolver interface {
	GetPodUID(pid int32) string
}

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

// workloadRateLimitMiddleware implements middleware.Middleware and enforces per-caller
// rate limiting on configured Workload API methods.
type workloadRateLimitMiddleware struct {
	limiters map[string]*perCallerRateLimiter
	resolver podUIDResolver
	metrics  telemetry.Metrics
}

// resolveRateLimitKey returns the rate limit key for the given caller. When a
// pod UID resolver is available and returns a pod UID, the key is prefixed with
// "pod:" to avoid collisions with OS UID keys. Otherwise it falls back to the
// OS UID prefixed with "uid:".
func (m workloadRateLimitMiddleware) resolveRateLimitKey(caller peertracker.CallerInfo) string {
	if m.resolver != nil {
		if podUID := m.resolver.GetPodUID(caller.PID); podUID != "" {
			return podKeyPrefix + podUID
		}
	}
	return uidKeyPrefix + strconv.FormatUint(uint64(caller.UID), 10)
}

func (m workloadRateLimitMiddleware) Preprocess(ctx context.Context, fullMethod string, _ any) (context.Context, error) {
	limiter, ok := m.limiters[fullMethod]
	if !ok {
		// Method not configured for rate limiting; pass through.
		return ctx, nil
	}

	ai, ok := peertracker.AuthInfoFromContext(ctx)
	if !ok {
		// No peer auth info available; pass through.
		return ctx, nil
	}

	key := m.resolveRateLimitKey(ai.Caller)
	if !limiter.Allow(key) {
		workloadapi.IncrRateLimitExceededCounter(m.metrics, fullMethod, keyType(key))

		return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded for %s", fullMethod)
	}
	return ctx, nil
}

func (m workloadRateLimitMiddleware) Postprocess(_ context.Context, _ string, _ bool, _ error) {}

// keyType returns "pod" if the key is a pod UID key, or "uid" otherwise.
func keyType(key string) string {
	if strings.HasPrefix(key, podKeyPrefix) {
		return "pod"
	}
	return "uid"
}

// buildWorkloadRateLimitMiddleware creates a rate limiting middleware from the given config.
// Returns nil if no limits are configured (all rates are 0).
func buildWorkloadRateLimitMiddleware(cfg WorkloadAPIRateLimitConfig, log logrus.FieldLogger, metrics telemetry.Metrics) middleware.Middleware {
	type methodLimit struct {
		method string
		limit  int
	}

	methods := []methodLimit{
		{"/SpiffeWorkloadAPI/FetchX509SVID", cfg.FetchX509SVID},
		{"/SpiffeWorkloadAPI/FetchX509Bundles", cfg.FetchX509Bundles},
		{"/SpiffeWorkloadAPI/FetchJWTSVID", cfg.FetchJWTSVID},
		{"/SpiffeWorkloadAPI/FetchJWTBundles", cfg.FetchJWTBundles},
		{"/SpiffeWorkloadAPI/ValidateJWTSVID", cfg.ValidateJWTSVID},
	}

	limiters := make(map[string]*perCallerRateLimiter)
	for _, ml := range methods {
		if ml.limit > 0 {
			limiters[ml.method] = newPerCallerRateLimiter(ml.limit)
		}
	}

	if len(limiters) == 0 {
		return nil
	}

	return workloadRateLimitMiddleware{
		limiters: limiters,
		resolver: newPodUIDResolver(log),
		metrics:  metrics,
	}
}
