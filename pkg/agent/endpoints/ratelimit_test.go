package endpoints

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/telemetry"
	testclock "github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// fakePodUIDResolver is a test fake for podUIDResolver.
type fakePodUIDResolver struct {
	// podUIDs maps PID to pod UID string. Empty string means "not a pod".
	podUIDs map[int32]string
}

func (f *fakePodUIDResolver) GetPodUID(pid int32) string {
	if f.podUIDs == nil {
		return ""
	}
	return f.podUIDs[pid]
}

func TestPerCallerRateLimiterAllow(t *testing.T) {
	lim := newPerCallerRateLimiter(2)

	// First two events for key "uid:1000" are allowed (limit=2, burst=2).
	assert.True(t, lim.Allow("uid:1000"))
	assert.True(t, lim.Allow("uid:1000"))
	// Third event is denied.
	assert.False(t, lim.Allow("uid:1000"))
}

func TestPerCallerRateLimiterIndependence(t *testing.T) {
	lim := newPerCallerRateLimiter(1)

	// Different keys have independent token buckets.
	assert.True(t, lim.Allow("uid:1000"))
	assert.True(t, lim.Allow("uid:2000"))
	// Both keys are now exhausted.
	assert.False(t, lim.Allow("uid:1000"))
	assert.False(t, lim.Allow("uid:2000"))
}

func TestPerCallerRateLimiterGC(t *testing.T) {
	mockClk := testclock.NewMock(t)
	oldClk := callerClk
	callerClk = mockClk
	defer func() { callerClk = oldClk }()

	lim := newPerCallerRateLimiter(1)

	// Exhaust key "uid:1000"'s token at time T.
	assert.True(t, lim.Allow("uid:1000"))
	assert.False(t, lim.Allow("uid:1000"))

	// Advance past the GC interval and trigger GC by accessing "uid:2000".
	// "uid:1000" moves from current to previous.
	mockClk.Add(callerGCInterval)
	assert.True(t, lim.Allow("uid:2000"))

	// Advance past the GC interval again and trigger GC by accessing "uid:3000".
	// "uid:1000" (in previous) is dropped entirely. "uid:2000" moves to previous.
	mockClk.Add(callerGCInterval)
	assert.True(t, lim.Allow("uid:3000"))

	// "uid:1000" has been GC'd. A new limiter is created with a fresh token bucket.
	// The allow should succeed since the new limiter starts with a full bucket.
	assert.True(t, lim.Allow("uid:1000"))
}

func TestPerCallerRateLimiterPreviousPreservation(t *testing.T) {
	mockClk := testclock.NewMock(t)
	oldClk := callerClk
	callerClk = mockClk
	defer func() { callerClk = oldClk }()

	lim := newPerCallerRateLimiter(1)

	// Create limiters for "uid:1000" and "uid:2000".
	assert.True(t, lim.Allow("uid:1000"))
	assert.True(t, lim.Allow("uid:2000"))
	assert.Equal(t, 2, len(lim.current))
	assert.Equal(t, 0, len(lim.previous))

	// Advance past GC interval and trigger GC via "uid:3000".
	// "uid:1000" and "uid:2000" move to previous.
	mockClk.Add(callerGCInterval)
	assert.True(t, lim.Allow("uid:3000"))
	assert.Equal(t, 1, len(lim.current))  // only "uid:3000"
	assert.Equal(t, 2, len(lim.previous)) // "uid:1000" and "uid:2000"

	// Access "uid:1000" — it gets promoted from previous to current (same limiter).
	lim.Allow("uid:1000")
	assert.Equal(t, 2, len(lim.current))  // "uid:1000" and "uid:3000"
	assert.Equal(t, 1, len(lim.previous)) // only "uid:2000"

	// Advance past GC interval again and trigger GC via "uid:4000".
	// "uid:2000" (in previous) is dropped. "uid:1000" and "uid:3000" move to previous.
	mockClk.Add(callerGCInterval)
	assert.True(t, lim.Allow("uid:4000"))
	assert.Equal(t, 1, len(lim.current))  // only "uid:4000"
	assert.Equal(t, 2, len(lim.previous)) // "uid:1000" and "uid:3000"

	// "uid:2000" is gone; accessing it creates a fresh limiter (new entry in current).
	assert.True(t, lim.Allow("uid:2000"))
	assert.Equal(t, 2, len(lim.current)) // "uid:4000" and "uid:2000" (new)
}

func TestWorkloadRateLimitMiddlewarePreprocess(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}
	cfg := WorkloadAPIRateLimitConfig{
		FetchX509SVID: 2,
	}
	m := buildWorkloadRateLimitMiddleware(cfg, log, metrics)
	require.NotNil(t, m)

	ctx := contextWithCallerInfo(1000, 100)

	// First two calls are allowed.
	retCtx, err := m.Preprocess(ctx, "/SpiffeWorkloadAPI/FetchX509SVID", nil)
	require.NoError(t, err)
	assert.NotNil(t, retCtx)

	retCtx, err = m.Preprocess(ctx, "/SpiffeWorkloadAPI/FetchX509SVID", nil)
	require.NoError(t, err)
	assert.NotNil(t, retCtx)

	// Third call is rejected.
	retCtx, err = m.Preprocess(ctx, "/SpiffeWorkloadAPI/FetchX509SVID", nil)
	require.Error(t, err)
	assert.Nil(t, retCtx)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "rate limit exceeded")
}

func TestWorkloadRateLimitMiddlewareUnconfiguredMethod(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}
	cfg := WorkloadAPIRateLimitConfig{
		FetchX509SVID: 1,
	}
	m := buildWorkloadRateLimitMiddleware(cfg, log, metrics)
	require.NotNil(t, m)

	ctx := contextWithCallerInfo(1000, 100)

	// FetchJWTSVID is not configured; it passes through even after FetchX509SVID is exhausted.
	_, err := m.Preprocess(ctx, "/SpiffeWorkloadAPI/FetchX509SVID", nil)
	require.NoError(t, err)
	_, err = m.Preprocess(ctx, "/SpiffeWorkloadAPI/FetchX509SVID", nil)
	require.Error(t, err) // exhausted

	_, err = m.Preprocess(ctx, "/SpiffeWorkloadAPI/FetchJWTSVID", nil)
	require.NoError(t, err)
}

func TestWorkloadRateLimitMiddlewareNonWorkloadMethod(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}
	cfg := WorkloadAPIRateLimitConfig{
		FetchX509SVID: 1,
	}
	m := buildWorkloadRateLimitMiddleware(cfg, log, metrics)
	require.NotNil(t, m)

	ctx := contextWithCallerInfo(1000, 100)

	// Non-Workload API methods always pass through.
	_, err := m.Preprocess(ctx, "/grpc.health.v1.Health/Check", nil)
	require.NoError(t, err)

	_, err = m.Preprocess(ctx, "/envoy.service.secret.v3.SecretDiscoveryService/FetchSecrets", nil)
	require.NoError(t, err)
}

func TestWorkloadRateLimitMiddlewareNoAuthInfo(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}
	cfg := WorkloadAPIRateLimitConfig{
		FetchX509SVID: 1,
	}
	m := buildWorkloadRateLimitMiddleware(cfg, log, metrics)
	require.NotNil(t, m)

	// Context without peer auth info passes through without rate limiting.
	ctx := context.Background()
	_, err := m.Preprocess(ctx, "/SpiffeWorkloadAPI/FetchX509SVID", nil)
	require.NoError(t, err)

	_, err = m.Preprocess(ctx, "/SpiffeWorkloadAPI/FetchX509SVID", nil)
	require.NoError(t, err)
}

func TestBuildWorkloadRateLimitMiddlewareAllZero(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}
	// All-zero config returns nil.
	m := buildWorkloadRateLimitMiddleware(WorkloadAPIRateLimitConfig{}, log, metrics)
	require.Nil(t, m)
}

func TestBuildWorkloadRateLimitMiddlewareAllMethods(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}
	cfg := WorkloadAPIRateLimitConfig{
		FetchX509SVID:    1,
		FetchX509Bundles: 2,
		FetchJWTSVID:     3,
		FetchJWTBundles:  4,
		ValidateJWTSVID:  5,
	}
	m := buildWorkloadRateLimitMiddleware(cfg, log, metrics)
	require.NotNil(t, m)

	wrlm, ok := m.(workloadRateLimitMiddleware)
	require.True(t, ok)
	assert.Len(t, wrlm.limiters, 5)
	assert.Contains(t, wrlm.limiters, "/SpiffeWorkloadAPI/FetchX509SVID")
	assert.Contains(t, wrlm.limiters, "/SpiffeWorkloadAPI/FetchX509Bundles")
	assert.Contains(t, wrlm.limiters, "/SpiffeWorkloadAPI/FetchJWTSVID")
	assert.Contains(t, wrlm.limiters, "/SpiffeWorkloadAPI/FetchJWTBundles")
	assert.Contains(t, wrlm.limiters, "/SpiffeWorkloadAPI/ValidateJWTSVID")
}

func TestWorkloadRateLimitMiddlewarePostprocess(t *testing.T) {
	// Postprocess is a no-op; just verify it doesn't panic.
	m := workloadRateLimitMiddleware{
		limiters: make(map[string]*perCallerRateLimiter),
		metrics:  telemetry.Blackhole{},
	}
	m.Postprocess(context.Background(), "/SpiffeWorkloadAPI/FetchX509SVID", true, nil)
}

func TestPerCallerRateLimiterTokenRefill(t *testing.T) {
	mockClk := testclock.NewMock(t)
	oldClk := callerClk
	callerClk = mockClk
	defer func() { callerClk = oldClk }()

	lim := newPerCallerRateLimiter(2)

	// Exhaust "uid:1000"'s tokens.
	assert.True(t, lim.Allow("uid:1000"))
	assert.True(t, lim.Allow("uid:1000"))
	assert.False(t, lim.Allow("uid:1000"))

	// Advance time by 1 second: 2 new tokens available (rate=2/s).
	mockClk.Add(time.Second)
	assert.True(t, lim.Allow("uid:1000"))
	assert.True(t, lim.Allow("uid:1000"))
	assert.False(t, lim.Allow("uid:1000"))
}

// --- Pod UID resolver tests ---

func TestWorkloadRateLimitMiddlewarePodUIDUsedWhenAvailable(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}

	// Two PIDs share UID 1000 but belong to different pods.
	resolver := &fakePodUIDResolver{
		podUIDs: map[int32]string{
			100: "pod-aaa",
			200: "pod-bbb",
		},
	}

	cfg := WorkloadAPIRateLimitConfig{FetchX509SVID: 1}
	m := buildWorkloadRateLimitMiddleware(cfg, log, metrics)
	require.NotNil(t, m)
	wrlm := m.(workloadRateLimitMiddleware)
	wrlm.resolver = resolver
	m = wrlm

	// PID 100 (pod-aaa): first call allowed.
	_, err := m.Preprocess(contextWithCallerInfo(1000, 100), "/SpiffeWorkloadAPI/FetchX509SVID", nil)
	require.NoError(t, err)
	// PID 100 (pod-aaa): second call rejected (limit=1).
	_, err = m.Preprocess(contextWithCallerInfo(1000, 100), "/SpiffeWorkloadAPI/FetchX509SVID", nil)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))

	// PID 200 (pod-bbb) also has UID 1000 but a different pod UID — independent bucket.
	_, err = m.Preprocess(contextWithCallerInfo(1000, 200), "/SpiffeWorkloadAPI/FetchX509SVID", nil)
	require.NoError(t, err)
}

func TestWorkloadRateLimitMiddlewareSamePodSharesBucket(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}

	// Two PIDs with different UIDs but the same pod UID — they share a bucket.
	resolver := &fakePodUIDResolver{
		podUIDs: map[int32]string{
			100: "pod-shared",
			200: "pod-shared",
		},
	}

	cfg := WorkloadAPIRateLimitConfig{FetchX509SVID: 2}
	m := buildWorkloadRateLimitMiddleware(cfg, log, metrics)
	require.NotNil(t, m)
	wrlm := m.(workloadRateLimitMiddleware)
	wrlm.resolver = resolver
	m = wrlm

	// First call from PID 100 — allowed.
	_, err := m.Preprocess(contextWithCallerInfo(1000, 100), "/SpiffeWorkloadAPI/FetchX509SVID", nil)
	require.NoError(t, err)
	// Second call from PID 200 (same pod) — allowed (still within burst).
	_, err = m.Preprocess(contextWithCallerInfo(2000, 200), "/SpiffeWorkloadAPI/FetchX509SVID", nil)
	require.NoError(t, err)
	// Third call (any PID in the same pod) — rejected; shared bucket exhausted.
	_, err = m.Preprocess(contextWithCallerInfo(1000, 100), "/SpiffeWorkloadAPI/FetchX509SVID", nil)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
}

func TestWorkloadRateLimitMiddlewareFallbackToUIDWhenNoPodUID(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}

	// Resolver returns empty string — no pod UID available.
	resolver := &fakePodUIDResolver{podUIDs: map[int32]string{}}

	cfg := WorkloadAPIRateLimitConfig{FetchX509SVID: 1}
	m := buildWorkloadRateLimitMiddleware(cfg, log, metrics)
	require.NotNil(t, m)
	wrlm := m.(workloadRateLimitMiddleware)
	wrlm.resolver = resolver
	m = wrlm

	ctx := contextWithCallerInfo(1000, 100)

	// First call allowed.
	_, err := m.Preprocess(ctx, "/SpiffeWorkloadAPI/FetchX509SVID", nil)
	require.NoError(t, err)
	// Second call rejected (falls back to UID-based key).
	_, err = m.Preprocess(ctx, "/SpiffeWorkloadAPI/FetchX509SVID", nil)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))

	// A different UID gets its own bucket.
	ctx2 := contextWithCallerInfo(2000, 200)
	_, err = m.Preprocess(ctx2, "/SpiffeWorkloadAPI/FetchX509SVID", nil)
	require.NoError(t, err)
}

func TestWorkloadRateLimitMiddlewareNilResolver(t *testing.T) {
	log, _ := test.NewNullLogger()
	metrics := telemetry.Blackhole{}

	cfg := WorkloadAPIRateLimitConfig{FetchX509SVID: 1}
	m := buildWorkloadRateLimitMiddleware(cfg, log, metrics)
	require.NotNil(t, m)
	wrlm := m.(workloadRateLimitMiddleware)
	wrlm.resolver = nil // explicitly nil, as on non-Linux
	m = wrlm

	ctx := contextWithCallerInfo(1000, 100)

	// Nil resolver falls back to OS UID.
	_, err := m.Preprocess(ctx, "/SpiffeWorkloadAPI/FetchX509SVID", nil)
	require.NoError(t, err)
	_, err = m.Preprocess(ctx, "/SpiffeWorkloadAPI/FetchX509SVID", nil)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
}

func TestResolveRateLimitKeyPodUID(t *testing.T) {
	m := workloadRateLimitMiddleware{
		resolver: &fakePodUIDResolver{
			podUIDs: map[int32]string{42: "abc-123"},
		},
	}
	key := m.resolveRateLimitKey(peertracker.CallerInfo{PID: 42, UID: 1000})
	assert.Equal(t, "pod:abc-123", key)
}

func TestResolveRateLimitKeyUID(t *testing.T) {
	m := workloadRateLimitMiddleware{
		resolver: &fakePodUIDResolver{podUIDs: map[int32]string{}},
	}
	key := m.resolveRateLimitKey(peertracker.CallerInfo{PID: 42, UID: 1000})
	assert.Equal(t, "uid:1000", key)
}

func TestKeyType(t *testing.T) {
	assert.Equal(t, "pod", keyType("pod:abc-123"))
	assert.Equal(t, "uid", keyType("uid:1000"))
	assert.Equal(t, "uid", keyType("pod")) // no "pod:" prefix
}

// TestWorkloadRateLimitMiddlewareMetricsOnRejection verifies that
// IncrRateLimitExceededCounter is called with the correct method and key_type
// labels when a request is rejected, and not called when a request is allowed.
func TestWorkloadRateLimitMiddlewareMetricsOnRejection(t *testing.T) {
	log, _ := test.NewNullLogger()
	fm := fakemetrics.New()

	cfg := WorkloadAPIRateLimitConfig{FetchJWTSVID: 1}
	m := buildWorkloadRateLimitMiddleware(cfg, log, fm)
	require.NotNil(t, m)
	wrlm := m.(workloadRateLimitMiddleware)
	wrlm.resolver = nil // use OS UID fallback
	m = wrlm

	ctx := contextWithCallerInfo(1000, 100)

	// First call is allowed — no rate limit metric emitted.
	_, err := m.Preprocess(ctx, "/SpiffeWorkloadAPI/FetchJWTSVID", nil)
	require.NoError(t, err)
	assert.Empty(t, fm.AllMetrics(), "no metric expected when request is allowed")

	// Second call is rejected — rate limit metric must be emitted.
	_, err = m.Preprocess(ctx, "/SpiffeWorkloadAPI/FetchJWTSVID", nil)
	require.Error(t, err)

	items := fm.AllMetrics()
	require.Len(t, items, 1)
	assert.Equal(t, fakemetrics.IncrCounterWithLabelsType, items[0].Type)
	assert.Equal(t, []string{telemetry.WorkloadAPI, telemetry.RateLimitExceeded}, items[0].Key)
	assert.Equal(t, float64(1), items[0].Val)
	require.Len(t, items[0].Labels, 2)
	assert.Equal(t, telemetry.Method, items[0].Labels[0].Name)
	// Label values are sanitized by the telemetry layer: '/' → '_'.
	assert.Equal(t, "_SpiffeWorkloadAPI_FetchJWTSVID", items[0].Labels[0].Value)
	assert.Equal(t, telemetry.KeyType, items[0].Labels[1].Name)
	assert.Equal(t, "uid", items[0].Labels[1].Value)
}

// TestWorkloadRateLimitMiddlewareMetricKeyTypePod verifies that the key_type
// label is "pod" when the rate limit key is resolved via pod UID.
func TestWorkloadRateLimitMiddlewareMetricKeyTypePod(t *testing.T) {
	log, _ := test.NewNullLogger()
	fm := fakemetrics.New()

	resolver := &fakePodUIDResolver{podUIDs: map[int32]string{100: "pod-abc"}}

	cfg := WorkloadAPIRateLimitConfig{FetchJWTSVID: 1}
	m := buildWorkloadRateLimitMiddleware(cfg, log, fm)
	require.NotNil(t, m)
	wrlm := m.(workloadRateLimitMiddleware)
	wrlm.resolver = resolver
	m = wrlm

	ctx := contextWithCallerInfo(1000, 100)

	// Exhaust the bucket.
	_, _ = m.Preprocess(ctx, "/SpiffeWorkloadAPI/FetchJWTSVID", nil)
	_, err := m.Preprocess(ctx, "/SpiffeWorkloadAPI/FetchJWTSVID", nil)
	require.Error(t, err)

	items := fm.AllMetrics()
	require.Len(t, items, 1)
	require.Len(t, items[0].Labels, 2)
	assert.Equal(t, telemetry.KeyType, items[0].Labels[1].Name)
	assert.Equal(t, "pod", items[0].Labels[1].Value)
}

// TestPerCallerRateLimiterConcurrency exercises the perCallerRateLimiter from
// many goroutines concurrently to validate the sync.RWMutex + double-checked
// locking pattern. Run with -race to detect data races.
func TestPerCallerRateLimiterConcurrency(t *testing.T) {
	const goroutines = 50
	const callsPerGoroutine = 200

	lim := newPerCallerRateLimiter(10)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			// Use 5 shared keys so goroutines contend on the same buckets.
			key := fmt.Sprintf("uid:%d", id%5)
			for j := 0; j < callsPerGoroutine; j++ {
				lim.Allow(key)
			}
		}(i)
	}
	wg.Wait()
}

// contextWithCallerInfo creates a context with the given UID and PID as peer auth info.
func contextWithCallerInfo(uid uint32, pid int32) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: peertracker.AuthInfo{
			Caller: peertracker.CallerInfo{UID: uid, PID: pid},
		},
	})
}
