package endpoints

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/telemetry/agent/workloadapi"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	callerGCInterval = time.Minute

	podKeyPrefix = "pod:"
	uidKeyPrefix = "uid:"
)

var (
	// callerClk can be overridden in tests to control time.
	callerClk clock.Clock = clock.New()
)

// podUIDResolver extracts a Kubernetes pod UID for the given process, returning
// an empty string if unavailable (e.g., not running in Kubernetes).
type podUIDResolver interface {
	GetPodUID(pid int32) string
}

// perCallerRateLimiter maintains per-caller rate limiters using a two-generation GC pattern.
// The key is a string that may represent a pod UID or OS UID (with a prefix to avoid collisions).
type perCallerRateLimiter struct {
	limit int

	mtx sync.RWMutex

	// previous holds all the limiters that were current at the GC.
	previous map[string]*rate.Limiter

	// current holds all the limiters that have been created or moved
	// from the previous limiters since the last GC.
	current map[string]*rate.Limiter

	// lastGC is the time of the last GC.
	lastGC time.Time
}

func newPerCallerRateLimiter(limit int) *perCallerRateLimiter {
	return &perCallerRateLimiter{
		limit:   limit,
		current: make(map[string]*rate.Limiter),
		lastGC:  callerClk.Now(),
	}
}

// Allow reports whether 1 event may happen at the current time for the given key.
func (l *perCallerRateLimiter) Allow(key string) bool {
	limiter := l.getLimiter(key)
	return limiter.AllowN(callerClk.Now(), 1)
}

func (l *perCallerRateLimiter) getLimiter(key string) *rate.Limiter {
	l.mtx.RLock()
	limiter, ok := l.current[key]
	if ok {
		l.mtx.RUnlock()
		return limiter
	}
	l.mtx.RUnlock()

	// A limiter does not exist for that key.
	l.mtx.Lock()
	defer l.mtx.Unlock()

	// Check the "current" entries in case another goroutine raced on this key.
	if limiter, ok = l.current[key]; ok {
		return limiter
	}

	// Then check the "previous" entries to see if a limiter exists for this
	// key as of the last GC. If so, move it to current and return it.
	if limiter, ok = l.previous[key]; ok {
		l.current[key] = limiter
		delete(l.previous, key)
		return limiter
	}

	// There is no limiter for this key. Before we create one, we should see
	// if we need to do GC.
	now := callerClk.Now()
	if now.Sub(l.lastGC) >= callerGCInterval {
		l.previous = l.current
		l.current = make(map[string]*rate.Limiter)
		l.lastGC = now
	}

	limiter = rate.NewLimiter(rate.Limit(l.limit), l.limit)
	l.current[key] = limiter
	return limiter
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
