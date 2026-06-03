package endpoints

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/endpoints/sdsv3"
	"github.com/spiffe/spire/pkg/agent/endpoints/workload"
	"github.com/spiffe/spire/pkg/common/ratelimit"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	testclock "github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func setupTestClock(t *testing.T) *testclock.Mock {
	mockClk := testclock.NewMock(t)
	oldOpts := perCallerRateLimiterOpts
	perCallerRateLimiterOpts = []ratelimit.Option{ratelimit.WithClock(mockClk)}
	t.Cleanup(func() { perCallerRateLimiterOpts = oldOpts })
	return mockClk
}

func TestPerCallerRateLimiterAllow(t *testing.T) {
	lim := newPerCallerRateLimiter(2)

	// First two events for key are allowed (limit=2, burst=2).
	assert.True(t, lim.Allow("spiffe://example.org/foo"))
	assert.True(t, lim.Allow("spiffe://example.org/foo"))
	// Third event is denied.
	assert.False(t, lim.Allow("spiffe://example.org/foo"))
}

func TestPerCallerRateLimiterIndependence(t *testing.T) {
	lim := newPerCallerRateLimiter(1)

	// Different keys have independent token buckets.
	assert.True(t, lim.Allow("spiffe://example.org/foo"))
	assert.True(t, lim.Allow("spiffe://example.org/bar"))
	// Both keys are now exhausted.
	assert.False(t, lim.Allow("spiffe://example.org/foo"))
	assert.False(t, lim.Allow("spiffe://example.org/bar"))
}

func TestPerCallerRateLimiterGC(t *testing.T) {
	mockClk := setupTestClock(t)

	lim := newPerCallerRateLimiter(1)

	// Exhaust key at time T.
	assert.True(t, lim.Allow("spiffe://example.org/foo"))
	assert.False(t, lim.Allow("spiffe://example.org/foo"))

	// Advance past the GC interval and trigger GC by accessing another key.
	mockClk.Add(ratelimit.GCInterval)
	assert.True(t, lim.Allow("spiffe://example.org/bar"))

	// Advance past the GC interval again and trigger GC.
	mockClk.Add(ratelimit.GCInterval)
	assert.True(t, lim.Allow("spiffe://example.org/baz"))

	// Original key has been GC'd. A new limiter is created with a fresh token bucket.
	assert.True(t, lim.Allow("spiffe://example.org/foo"))
}

func TestPerCallerRateLimiterPreviousPreservation(t *testing.T) {
	mockClk := setupTestClock(t)

	lim := newPerCallerRateLimiter(1)

	assert.True(t, lim.Allow("spiffe://example.org/foo"))
	assert.True(t, lim.Allow("spiffe://example.org/bar"))

	// Advance past GC interval and trigger GC.
	mockClk.Add(ratelimit.GCInterval)
	assert.True(t, lim.Allow("spiffe://example.org/baz"))

	// Access foo — it gets promoted from previous to current (same limiter).
	lim.Allow("spiffe://example.org/foo")

	// Advance past GC interval again and trigger GC.
	mockClk.Add(ratelimit.GCInterval)
	assert.True(t, lim.Allow("spiffe://example.org/qux"))

	// bar is gone; accessing it creates a fresh limiter.
	assert.True(t, lim.Allow("spiffe://example.org/bar"))
}

func TestPerCallerRateLimiterTokenRefill(t *testing.T) {
	mockClk := setupTestClock(t)

	lim := newPerCallerRateLimiter(2)

	// Exhaust tokens.
	assert.True(t, lim.Allow("spiffe://example.org/foo"))
	assert.True(t, lim.Allow("spiffe://example.org/foo"))
	assert.False(t, lim.Allow("spiffe://example.org/foo"))

	// Advance time by 1 second: 2 new tokens available (rate=2/s).
	mockClk.Add(time.Second)
	assert.True(t, lim.Allow("spiffe://example.org/foo"))
	assert.True(t, lim.Allow("spiffe://example.org/foo"))
	assert.False(t, lim.Allow("spiffe://example.org/foo"))
}

// TestPerCallerRateLimiterConcurrency exercises the perCallerRateLimiter from
// many goroutines concurrently. Run with -race to detect data races.
func TestPerCallerRateLimiterConcurrency(t *testing.T) {
	const goroutines = 50
	const callsPerGoroutine = 200

	lim := newPerCallerRateLimiter(10)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(id int) {
			defer wg.Done()
			// Use 5 shared keys so goroutines contend on the same buckets.
			key := fmt.Sprintf("spiffe://example.org/workload-%d", id%5)
			for range callsPerGoroutine {
				lim.Allow(key)
			}
		}(i)
	}
	wg.Wait()
}

// selectors builds a []*common.Selector from alternating type/value strings.
func selectors(pairs ...string) []*common.Selector {
	if len(pairs)%2 != 0 {
		panic("selectors: odd number of arguments")
	}
	out := make([]*common.Selector, 0, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, &common.Selector{Type: pairs[i], Value: pairs[i+1]})
	}
	return out
}

func TestSelectorSetKey(t *testing.T) {
	// Same selectors in different order produce the same key.
	s1 := selectors("k8s", "pod:a", "unix", "uid:1000")
	s2 := selectors("unix", "uid:1000", "k8s", "pod:a")
	assert.Equal(t, selectorSetKey(s1), selectorSetKey(s2))

	// Different selector sets produce different keys.
	s3 := selectors("k8s", "pod:b", "unix", "uid:1000")
	assert.NotEqual(t, selectorSetKey(s1), selectorSetKey(s3))

	// Selectors whose concatenation would collide without separators map to
	// distinct keys (type "a"/value "bc" vs type "ab"/value "c").
	assert.NotEqual(t, selectorSetKey(selectors("a", "bc")), selectorSetKey(selectors("ab", "c")))

	// Empty selector set maps to the shared unattested bucket.
	assert.Equal(t, "<unattested>", selectorSetKey(nil))
	assert.Equal(t, "<unattested>", selectorSetKey([]*common.Selector{}))
}

func TestWorkloadRateLimiterRateLimit(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}
	cfg := WorkloadAPIRateLimitConfig{
		FetchX509SVID: 2,
	}
	rl := NewWorkloadRateLimiter(cfg, log, metrics)
	require.NotNil(t, rl)

	sel := selectors("k8s", "pod:foo")

	// First two calls are allowed.
	require.NoError(t, rl.RateLimit(workload.MethodFetchX509SVID, sel))
	require.NoError(t, rl.RateLimit(workload.MethodFetchX509SVID, sel))

	// Third call is rejected.
	err := rl.RateLimit(workload.MethodFetchX509SVID, sel)
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "rate limit exceeded")
}

func TestWorkloadRateLimiterUnconfiguredMethod(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}
	cfg := WorkloadAPIRateLimitConfig{
		FetchX509SVID: 1,
	}
	rl := NewWorkloadRateLimiter(cfg, log, metrics)
	require.NotNil(t, rl)

	sel := selectors("k8s", "pod:foo")

	// Exhaust FetchX509SVID.
	require.NoError(t, rl.RateLimit(workload.MethodFetchX509SVID, sel))
	require.Error(t, rl.RateLimit(workload.MethodFetchX509SVID, sel))

	// FetchJWTSVID is not configured; it passes through.
	require.NoError(t, rl.RateLimit(workload.MethodFetchJWTSVID, sel))
}

func TestWorkloadRateLimiterNonWorkloadMethod(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}
	cfg := WorkloadAPIRateLimitConfig{
		FetchX509SVID: 1,
	}
	rl := NewWorkloadRateLimiter(cfg, log, metrics)
	require.NotNil(t, rl)

	sel := selectors("k8s", "pod:foo")

	// Non-Workload API methods always pass through.
	require.NoError(t, rl.RateLimit("/grpc.health.v1.Health/Check", sel))
	require.NoError(t, rl.RateLimit("/envoy.service.secret.v3.SecretDiscoveryService/FetchSecrets", sel))
}

func TestNewWorkloadRateLimiterAllZero(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}
	// All-zero config still returns a usable limiter; every method passes through.
	rl := NewWorkloadRateLimiter(WorkloadAPIRateLimitConfig{}, log, metrics)
	require.NotNil(t, rl)
	assert.Empty(t, rl.limiters)
	require.NoError(t, rl.RateLimit(workload.MethodFetchX509SVID, selectors("k8s", "pod:foo")))
	require.NoError(t, rl.RateLimit(workload.MethodFetchJWTSVID, nil))
}

func TestNewWorkloadRateLimiterBothMethods(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}
	cfg := WorkloadAPIRateLimitConfig{
		FetchX509SVID: 1,
		FetchJWTSVID:  3,
	}
	rl := NewWorkloadRateLimiter(cfg, log, metrics)
	require.NotNil(t, rl)
	assert.Len(t, rl.limiters, 2)
	assert.Contains(t, rl.limiters, workload.MethodFetchX509SVID)
	assert.Contains(t, rl.limiters, workload.MethodFetchJWTSVID)
}

func TestNewWorkloadRateLimiterAllSixMethods(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}
	cfg := WorkloadAPIRateLimitConfig{
		FetchX509SVID:    1,
		FetchJWTSVID:     2,
		FetchX509Bundles: 3,
		FetchJWTBundles:  4,
		StreamSecrets:    5,
		FetchSecrets:     6,
	}
	rl := NewWorkloadRateLimiter(cfg, log, metrics)
	require.NotNil(t, rl)
	assert.Len(t, rl.limiters, 6)
	assert.Contains(t, rl.limiters, workload.MethodFetchX509SVID)
	assert.Contains(t, rl.limiters, workload.MethodFetchJWTSVID)
	assert.Contains(t, rl.limiters, workload.MethodFetchX509Bundles)
	assert.Contains(t, rl.limiters, workload.MethodFetchJWTBundles)
	assert.Contains(t, rl.limiters, sdsv3.MethodStreamSecrets)
	assert.Contains(t, rl.limiters, sdsv3.MethodFetchSecrets)
}

// TestWorkloadRateLimiterSelectorSetIndependence verifies that two callers
// with different selector sets each have independent token buckets.
func TestWorkloadRateLimiterSelectorSetIndependence(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}
	cfg := WorkloadAPIRateLimitConfig{
		FetchJWTSVID: 1,
	}
	rl := NewWorkloadRateLimiter(cfg, log, metrics)
	require.NotNil(t, rl)

	selA := selectors("k8s", "pod:a")
	selB := selectors("k8s", "pod:b")

	// Exhaust pod:a bucket.
	require.NoError(t, rl.RateLimit(workload.MethodFetchJWTSVID, selA))
	require.Error(t, rl.RateLimit(workload.MethodFetchJWTSVID, selA))

	// pod:b has its own bucket and is still allowed.
	require.NoError(t, rl.RateLimit(workload.MethodFetchJWTSVID, selB))
}

// TestWorkloadRateLimiterSelectorSetOrdering verifies that selectors with the
// same elements in different order map to the same bucket.
func TestWorkloadRateLimiterSelectorSetOrdering(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}
	cfg := WorkloadAPIRateLimitConfig{
		FetchJWTSVID: 1,
	}
	rl := NewWorkloadRateLimiter(cfg, log, metrics)
	require.NotNil(t, rl)

	// Same selectors, different order — must share one bucket.
	sel1 := selectors("k8s", "pod:x", "unix", "uid:500")
	sel2 := selectors("unix", "uid:500", "k8s", "pod:x")

	require.NoError(t, rl.RateLimit(workload.MethodFetchJWTSVID, sel1))
	// sel2 resolves to the same key, so the bucket is exhausted.
	require.Error(t, rl.RateLimit(workload.MethodFetchJWTSVID, sel2))
}

// TestWorkloadRateLimiterUnattestedBucket verifies that callers with no
// selectors share a single "<unattested>" bucket.
func TestWorkloadRateLimiterUnattestedBucket(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}
	cfg := WorkloadAPIRateLimitConfig{
		FetchJWTSVID: 1,
	}
	rl := NewWorkloadRateLimiter(cfg, log, metrics)
	require.NotNil(t, rl)

	// First nil-selector call consumes the single token.
	require.NoError(t, rl.RateLimit(workload.MethodFetchJWTSVID, nil))

	// A second nil-selector call (different caller, same empty set) is rejected
	// because they share the "<unattested>" bucket.
	require.Error(t, rl.RateLimit(workload.MethodFetchJWTSVID, []*common.Selector{}))
}

// TestWorkloadRateLimiterMetricsOnRejection verifies that
// IncrRateLimitExceededCounter is called with the correct method label
// when a request is rejected.
func TestWorkloadRateLimiterMetricsOnRejection(t *testing.T) {
	log, _ := test.NewNullLogger()
	fm := fakemetrics.New()

	cfg := WorkloadAPIRateLimitConfig{FetchJWTSVID: 1}
	rl := NewWorkloadRateLimiter(cfg, log, fm)
	require.NotNil(t, rl)

	sel := selectors("k8s", "pod:foo")

	// First call is allowed — no rate limit metric emitted.
	require.NoError(t, rl.RateLimit(workload.MethodFetchJWTSVID, sel))
	assert.Empty(t, fm.AllMetrics(), "no metric expected when request is allowed")

	// Second call is rejected — rate limit metric must be emitted.
	err := rl.RateLimit(workload.MethodFetchJWTSVID, sel)
	require.Error(t, err)

	items := fm.AllMetrics()
	require.Len(t, items, 1)
	assert.Equal(t, fakemetrics.IncrCounterWithLabelsType, items[0].Type)
	assert.Equal(t, []string{telemetry.WorkloadAPI, telemetry.RateLimitExceeded}, items[0].Key)
	assert.Equal(t, float64(1), items[0].Val)
	require.Len(t, items[0].Labels, 1)
	assert.Equal(t, telemetry.Method, items[0].Labels[0].Name)
	// Label values are sanitized by the telemetry layer: '/' → '_'.
	assert.Equal(t, "_SpiffeWorkloadAPI_FetchJWTSVID", items[0].Labels[0].Value)
}
