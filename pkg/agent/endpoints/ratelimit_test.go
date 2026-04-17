package endpoints

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/endpoints/workload"
	"github.com/spiffe/spire/pkg/common/ratelimit"
	"github.com/spiffe/spire/pkg/common/telemetry"
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

func TestWorkloadRateLimiterRateLimit(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}
	cfg := WorkloadAPIRateLimitConfig{
		FetchX509SVID: 2,
	}
	rl := NewWorkloadRateLimiter(cfg, log, metrics)
	require.NotNil(t, rl)

	ids := []string{"spiffe://example.org/foo"}

	// First two calls are allowed.
	require.NoError(t, rl.RateLimit(workload.MethodFetchX509SVID, ids))
	require.NoError(t, rl.RateLimit(workload.MethodFetchX509SVID, ids))

	// Third call is rejected.
	err := rl.RateLimit(workload.MethodFetchX509SVID, ids)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
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

	ids := []string{"spiffe://example.org/foo"}

	// Exhaust FetchX509SVID.
	require.NoError(t, rl.RateLimit(workload.MethodFetchX509SVID, ids))
	require.Error(t, rl.RateLimit(workload.MethodFetchX509SVID, ids))

	// FetchJWTSVID is not configured; it passes through.
	require.NoError(t, rl.RateLimit(workload.MethodFetchJWTSVID, ids))
}

func TestWorkloadRateLimiterNonWorkloadMethod(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}
	cfg := WorkloadAPIRateLimitConfig{
		FetchX509SVID: 1,
	}
	rl := NewWorkloadRateLimiter(cfg, log, metrics)
	require.NotNil(t, rl)

	ids := []string{"spiffe://example.org/foo"}

	// Non-Workload API methods always pass through.
	require.NoError(t, rl.RateLimit("/grpc.health.v1.Health/Check", ids))
	require.NoError(t, rl.RateLimit("/envoy.service.secret.v3.SecretDiscoveryService/FetchSecrets", ids))
}

func TestWorkloadRateLimiterNilIsNoOp(t *testing.T) {
	var rl *WorkloadRateLimiter
	// Nil rate limiter always allows.
	require.NoError(t, rl.RateLimit(workload.MethodFetchX509SVID, []string{"spiffe://example.org/foo"}))
	require.NoError(t, rl.RateLimit(workload.MethodFetchX509SVID, []string{"spiffe://example.org/foo"}))
}

func TestNewWorkloadRateLimiterAllZero(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}
	// All-zero config returns nil.
	rl := NewWorkloadRateLimiter(WorkloadAPIRateLimitConfig{}, log, metrics)
	require.Nil(t, rl)
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

func TestWorkloadRateLimiterIndependentSPIFFEIDs(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}
	cfg := WorkloadAPIRateLimitConfig{
		FetchJWTSVID: 1,
	}
	rl := NewWorkloadRateLimiter(cfg, log, metrics)
	require.NotNil(t, rl)

	// Different SPIFFE IDs have independent rate limits.
	require.NoError(t, rl.RateLimit(workload.MethodFetchJWTSVID, []string{"spiffe://example.org/foo"}))
	require.Error(t, rl.RateLimit(workload.MethodFetchJWTSVID, []string{"spiffe://example.org/foo"}))

	// A different SPIFFE ID is not affected.
	require.NoError(t, rl.RateLimit(workload.MethodFetchJWTSVID, []string{"spiffe://example.org/bar"}))
}

func TestWorkloadRateLimiterMultipleSPIFFEIDs(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}
	cfg := WorkloadAPIRateLimitConfig{
		FetchJWTSVID: 1,
	}
	rl := NewWorkloadRateLimiter(cfg, log, metrics)
	require.NotNil(t, rl)

	// First call with two SPIFFE IDs: allowed (both have tokens).
	require.NoError(t, rl.RateLimit(workload.MethodFetchJWTSVID, []string{
		"spiffe://example.org/foo",
		"spiffe://example.org/bar",
	}))

	// Second call: foo is exhausted, so the whole call is rejected.
	err := rl.RateLimit(workload.MethodFetchJWTSVID, []string{
		"spiffe://example.org/foo",
		"spiffe://example.org/bar",
	})
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
}

func TestWorkloadRateLimiterEmptySPIFFEIDs(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}
	cfg := WorkloadAPIRateLimitConfig{
		FetchJWTSVID: 1,
	}
	rl := NewWorkloadRateLimiter(cfg, log, metrics)
	require.NotNil(t, rl)

	// No SPIFFE IDs means no rate limit check is needed.
	require.NoError(t, rl.RateLimit(workload.MethodFetchJWTSVID, nil))
	require.NoError(t, rl.RateLimit(workload.MethodFetchJWTSVID, []string{}))
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

	ids := []string{"spiffe://example.org/foo"}

	// First call is allowed — no rate limit metric emitted.
	require.NoError(t, rl.RateLimit(workload.MethodFetchJWTSVID, ids))
	assert.Empty(t, fm.AllMetrics(), "no metric expected when request is allowed")

	// Second call is rejected — rate limit metric must be emitted.
	err := rl.RateLimit(workload.MethodFetchJWTSVID, ids)
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
