package endpoints

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/ratelimit"
	"github.com/spiffe/spire/proto/spire/common"
	testclock "github.com/spiffe/spire/test/clock"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

type queueCall struct {
	id     string
	cancel context.CancelFunc
	result <-chan error
}

func queueClients(t *testing.T, policy map[string]int, rate WorkloadAPIRateLimitConfig, options ...func(*Config)) streamTestClients {
	t.Helper()
	c := newStreamTestClients(t, policy, rate, nil, options...)
	c.manager.subscribedIDs = make(chan string, 64)
	return c
}

func queueStart(t *testing.T, c streamTestClients, method string, caller int, timeout time.Duration) queueCall {
	t.Helper()
	cancel, result := startStream(t, c, method, caller, timeout)
	return queueCall{strconv.FormatInt(c.sequence.Load(), 10), cancel, result}
}

func queueStats(t *testing.T, c streamTestClients) (int, int) {
	t.Helper()
	m := reflect.ValueOf(c.endpoint).MethodByName("WorkloadAPIStreamStats")
	require.True(t, m.IsValid(), "endpoints must expose active and pending stream counts")
	require.Equal(t, 0, m.Type().NumIn())
	require.Equal(t, 1, m.Type().NumOut())
	s := m.Call(nil)[0]
	require.Equal(t, reflect.Struct, s.Kind())
	active, pending := s.FieldByName("Active"), s.FieldByName("Pending")
	require.True(t, active.IsValid() && pending.IsValid())
	require.Equal(t, reflect.Int, active.Kind())
	require.Equal(t, reflect.Int, pending.Kind())
	return int(active.Int()), int(pending.Int())
}

func waitQueueStats(t *testing.T, c streamTestClients, active, pending int) {
	t.Helper()
	require.Eventually(t, func() bool {
		a, p := queueStats(t, c)
		return a == active && p == pending
	}, 5*time.Second, time.Millisecond, "want active=%d pending=%d", active, pending)
}

func queueAdmitted(t *testing.T, c streamTestClients, calls ...queueCall) {
	t.Helper()
	var got, want []string
	for _, call := range calls {
		want = append(want, call.id)
		select {
		case id := <-c.manager.subscribedIDs:
			got = append(got, id)
		case <-time.After(5 * time.Second):
			t.Fatal("eligible stream was not admitted")
		}
		waitStreamEvent(t, c.manager.started, "admitted stream")
		select {
		case <-c.manager.subscriptions:
		case <-time.After(5 * time.Second):
			t.Fatal("admitted stream did not subscribe")
		}
	}
	require.ElementsMatch(t, want, got, "admission must select the oldest eligible calls")
}

func queueStop(t *testing.T, c streamTestClients, call queueCall, admitted bool) {
	t.Helper()
	call.cancel()
	expectStreamError(t, call.result, codes.Canceled)
	if admitted {
		waitStreamEvent(t, c.manager.finished, "admitted stream cleanup")
	}
}

func TestActiveStreamLimitsQueueFIFOAcrossAPIs(t *testing.T) {
	for i, method := range policyMethods {
		t.Run(method, func(t *testing.T) {
			c := queueClients(t, map[string]int{"Global": 1, "MaxPending": 2}, WorkloadAPIRateLimitConfig{})
			holder := queueStart(t, c, method, 1, 30*time.Second)
			queueAdmitted(t, c, holder)
			first := queueStart(t, c, policyMethods[(i+1)%4], 3, 30*time.Second)
			waitQueueStats(t, c, 1, 1)
			second := queueStart(t, c, policyMethods[(i+2)%4], 7, 30*time.Second)
			waitQueueStats(t, c, 1, 2)
			require.Empty(t, streamLimitRejectionMetrics(c.metrics.AllMetrics(), method))
			denyLifecycleStream(t, c, method, 10)
			metrics := streamLimitRejectionMetrics(c.metrics.AllMetrics(), method)
			require.Len(t, metrics, 1, "full pending queue must count the rejected opening exactly once")
			require.Equal(t, float64(1), metrics[0].Val)
			require.NotEqual(t, []string{"workload_api", "rate_limit_exceeded"}, metrics[0].Key)
			require.Len(t, metrics[0].Labels, 1, "queue overflow metric must have only the method label")
			require.Equal(t, "method", metrics[0].Labels[0].Name)
			require.Contains(t, normalizeStreamMetricIdentity(metrics[0].Labels[0].Value), normalizeStreamMetricIdentity(method))
			queueStop(t, c, holder, true)
			queueAdmitted(t, c, first)
			waitQueueStats(t, c, 1, 1)
			queueStop(t, c, first, true)
			queueAdmitted(t, c, second)
			waitQueueStats(t, c, 1, 0)
			queueStop(t, c, second, true)
			waitQueueStats(t, c, 0, 0)
		})
	}
}

func TestActiveStreamLimitsQueueSkipsIneligible(t *testing.T) {
	c := queueClients(t, map[string]int{"Global": 3, "PerWorkload": 2, "FetchJWTBundles": 1, "MaxPending": 4}, WorkloadAPIRateLimitConfig{})
	jwt := queueStart(t, c, "FetchJWTBundles", 7, 30*time.Second)
	queueAdmitted(t, c, jwt)
	sds := queueStart(t, c, "StreamSecrets", 8, 30*time.Second)
	queueAdmitted(t, c, sds)
	other := queueStart(t, c, "FetchX509Bundles", 3, 30*time.Second)
	queueAdmitted(t, c, other)
	oldest := queueStart(t, c, "FetchJWTBundles", 8, 30*time.Second)
	waitQueueStats(t, c, 3, 1)
	middle := queueStart(t, c, "StreamSecrets", 7, 30*time.Second)
	waitQueueStats(t, c, 3, 2)
	last := queueStart(t, c, "FetchX509SVID", 3, 30*time.Second)
	waitQueueStats(t, c, 3, 3)
	queueStop(t, c, other, true)
	queueAdmitted(t, c, last)
	waitQueueStats(t, c, 3, 2)
	queueStop(t, c, sds, true)
	queueAdmitted(t, c, middle)
	waitQueueStats(t, c, 3, 1)
	queueStop(t, c, jwt, true)
	queueAdmitted(t, c, oldest)
	waitQueueStats(t, c, 3, 0)
	queueStop(t, c, oldest, true)
	queueStop(t, c, middle, true)
	queueStop(t, c, last, true)
	waitQueueStats(t, c, 0, 0)
}

func TestActiveStreamLimitsQueueNewArrival(t *testing.T) {
	c := queueClients(t, map[string]int{"Global": 2, "FetchJWTBundles": 1, "MaxPending": 3}, WorkloadAPIRateLimitConfig{})
	first := queueStart(t, c, "FetchJWTBundles", 1, 30*time.Second)
	queueAdmitted(t, c, first)
	blocked := queueStart(t, c, "FetchJWTBundles", 2, 30*time.Second)
	waitQueueStats(t, c, 1, 1)
	other := queueStart(t, c, "StreamSecrets", 3, 30*time.Second)
	queueAdmitted(t, c, other)
	waitQueueStats(t, c, 2, 1)
	require.NoError(t, replaceStreamPolicy(t, c, map[string]int{"Global": 1, "MaxPending": 3}))
	queueStop(t, c, other, true)
	waitQueueStats(t, c, 1, 1)
	released := make(chan struct{})
	go func() { first.cancel(); close(released) }()
	newcomer := queueStart(t, c, "FetchX509Bundles", 10, 30*time.Second)
	<-released
	expectStreamError(t, first.result, codes.Canceled)
	waitStreamEvent(t, c.manager.finished, "released holder")
	queueAdmitted(t, c, blocked)
	waitQueueStats(t, c, 1, 1)
	queueStop(t, c, blocked, true)
	queueAdmitted(t, c, newcomer)
	queueStop(t, c, newcomer, true)
	waitQueueStats(t, c, 0, 0)
}

func TestActiveStreamLimitsQueuePolicyReplacement(t *testing.T) {
	c := queueClients(t, map[string]int{"Global": 1, "MaxPending": 3}, WorkloadAPIRateLimitConfig{})
	holder := queueStart(t, c, "FetchX509SVID", 1, 30*time.Second)
	queueAdmitted(t, c, holder)
	first := queueStart(t, c, "StreamSecrets", 3, 30*time.Second)
	waitQueueStats(t, c, 1, 1)
	second := queueStart(t, c, "FetchJWTBundles", 7, 30*time.Second)
	waitQueueStats(t, c, 1, 2)
	last := queueStart(t, c, "FetchX509Bundles", 10, 30*time.Second)
	waitQueueStats(t, c, 1, 3)
	require.NoError(t, replaceStreamPolicy(t, c, map[string]int{"Global": 2, "MaxPending": 1}))
	a, p := queueStats(t, c)
	require.Equal(t, 2, a)
	require.Equal(t, 1, p)
	queueAdmitted(t, c, first)
	expectStreamError(t, last.result, codes.ResourceExhausted)
	last.cancel()
	require.Len(t, streamLimitRejectionMetrics(c.metrics.AllMetrics(), "FetchX509Bundles"), 1)
	require.NoError(t, replaceStreamPolicy(t, c, map[string]int{"Global": 3}))
	a, p = queueStats(t, c)
	require.Equal(t, 3, a)
	require.Zero(t, p)
	queueAdmitted(t, c, second)
	require.Empty(t, streamLimitRejectionMetrics(c.metrics.AllMetrics(), "FetchJWTBundles"))
	queueStop(t, c, holder, true)
	queueStop(t, c, first, true)
	queueStop(t, c, second, true)
	waitQueueStats(t, c, 0, 0)
}

func TestActiveStreamLimitsQueueInvalidUpdate(t *testing.T) {
	for _, field := range append([]string{"Global", "PerWorkload", "MaxPending"}, policyMethods...) {
		t.Run(field, func(t *testing.T) {
			c := queueClients(t, map[string]int{"Global": 1, "MaxPending": 2}, WorkloadAPIRateLimitConfig{})
			holder := queueStart(t, c, "FetchJWTBundles", 1, 30*time.Second)
			queueAdmitted(t, c, holder)
			first := queueStart(t, c, "StreamSecrets", 3, 30*time.Second)
			waitQueueStats(t, c, 1, 1)
			last := queueStart(t, c, "FetchX509Bundles", 10, 30*time.Second)
			waitQueueStats(t, c, 1, 2)
			replacement := map[string]int{"Global": 4, "MaxPending": 0}
			replacement[field] = -1
			err := replaceStreamPolicy(t, c, replacement)
			require.Error(t, err)
			if field == "MaxPending" {
				require.Contains(t, err.Error(), "max_pending")
			}
			a, p := queueStats(t, c)
			require.Equal(t, 1, a)
			require.Equal(t, 2, p)
			queueStop(t, c, holder, true)
			queueAdmitted(t, c, first)
			queueStop(t, c, first, true)
			queueAdmitted(t, c, last)
			queueStop(t, c, last, true)
			waitQueueStats(t, c, 0, 0)
		})
	}
}

func TestActiveStreamLimitsQueueDisabledEvicts(t *testing.T) {
	c := queueClients(t, map[string]int{"Global": 1, "MaxPending": 2}, WorkloadAPIRateLimitConfig{})
	holder := queueStart(t, c, "FetchJWTBundles", 1, 30*time.Second)
	queueAdmitted(t, c, holder)
	first := queueStart(t, c, "StreamSecrets", 3, 30*time.Second)
	waitQueueStats(t, c, 1, 1)
	second := queueStart(t, c, "StreamSecrets", 10, 30*time.Second)
	waitQueueStats(t, c, 1, 2)
	require.NoError(t, replaceStreamPolicy(t, c, map[string]int{"Global": 1}))
	a, p := queueStats(t, c)
	require.Equal(t, 1, a)
	require.Zero(t, p)
	for _, q := range []queueCall{first, second} {
		expectStreamError(t, q.result, codes.ResourceExhausted)
		q.cancel()
	}
	require.Len(t, streamLimitRejectionMetrics(c.metrics.AllMetrics(), "StreamSecrets"), 2)
	denyLifecycleStream(t, c, "StreamSecrets", 3)
	require.Len(t, streamLimitRejectionMetrics(c.metrics.AllMetrics(), "StreamSecrets"), 3)
	for _, metric := range streamLimitRejectionMetrics(c.metrics.AllMetrics(), "StreamSecrets") {
		require.Equal(t, float64(1), metric.Val)
		require.Len(t, metric.Labels, 1)
		require.Equal(t, "method", metric.Labels[0].Name)
	}

	queueStop(t, c, holder, true)
	waitQueueStats(t, c, 0, 0)
}

func TestActiveStreamLimitsQueueCancellation(t *testing.T) {
	for _, method := range policyMethods {
		t.Run(method, func(t *testing.T) {
			c := queueClients(t, map[string]int{"Global": 1, "MaxPending": 2}, WorkloadAPIRateLimitConfig{})
			holder := queueStart(t, c, "FetchJWTBundles", 3, 30*time.Second)
			queueAdmitted(t, c, holder)
			first := queueStart(t, c, method, 1, 30*time.Second)
			waitQueueStats(t, c, 1, 1)
			retained := queueStart(t, c, method, 7, 30*time.Second)
			waitQueueStats(t, c, 1, 2)
			queueStop(t, c, first, false)
			waitQueueStats(t, c, 1, 1)
			last := queueStart(t, c, method, 10, 30*time.Second)
			waitQueueStats(t, c, 1, 2)
			queueStop(t, c, holder, true)
			queueAdmitted(t, c, retained)
			queueStop(t, c, retained, true)
			queueAdmitted(t, c, last)
			queueStop(t, c, last, true)
			waitQueueStats(t, c, 0, 0)
			require.Empty(t, streamLimitRejectionMetrics(c.metrics.AllMetrics(), method))
		})
	}
}

func TestActiveStreamLimitsQueueDeadline(t *testing.T) {
	for _, method := range policyMethods {
		t.Run(method, func(t *testing.T) {
			c := queueClients(t, map[string]int{"Global": 1, "MaxPending": 1}, WorkloadAPIRateLimitConfig{})
			holder := queueStart(t, c, "FetchJWTBundles", 3, 30*time.Second)
			queueAdmitted(t, c, holder)
			expired := queueStart(t, c, method, 1, 2*time.Second)
			waitQueueStats(t, c, 1, 1)
			expectStreamError(t, expired.result, codes.DeadlineExceeded)
			expired.cancel()
			waitQueueStats(t, c, 1, 0)
			next := queueStart(t, c, method, 7, 30*time.Second)
			waitQueueStats(t, c, 1, 1)
			queueStop(t, c, holder, true)
			queueAdmitted(t, c, next)
			queueStop(t, c, next, true)
			waitQueueStats(t, c, 0, 0)
			require.Empty(t, streamLimitRejectionMetrics(c.metrics.AllMetrics(), method))
		})
	}
}

func TestActiveStreamLimitsQueueCancellationGrantRace(t *testing.T) {
	for i := range 16 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			c := queueClients(t, map[string]int{"Global": 1, "MaxPending": 1}, WorkloadAPIRateLimitConfig{})
			holder := queueStart(t, c, "FetchJWTBundles", 3, 30*time.Second)
			queueAdmitted(t, c, holder)
			queued := queueStart(t, c, policyMethods[i%4], 1, 30*time.Second)
			waitQueueStats(t, c, 1, 1)
			var wg sync.WaitGroup
			wg.Add(2)
			start := make(chan struct{})
			go func() { defer wg.Done(); <-start; queued.cancel() }()
			go func() { defer wg.Done(); <-start; holder.cancel() }()
			close(start)
			wg.Wait()
			expectStreamError(t, holder.result, codes.Canceled)
			expectStreamError(t, queued.result, codes.Canceled)
			waitQueueStats(t, c, 0, 0)
			// With waiting disabled, any leaked reservation would reject this call.
			require.NoError(t, replaceStreamPolicy(t, c, map[string]int{"Global": 1}))
			cancel, result := startStream(t, c, "FetchX509Bundles", 10, 30*time.Second)
			waitQueueStats(t, c, 1, 0)
			cancel()
			expectStreamError(t, result, codes.Canceled)
			waitQueueStats(t, c, 0, 0)
		})
	}
}

func TestActiveStreamLimitsQueueAdmissionFailureHandoff(t *testing.T) {
	for _, method := range policyMethods {
		t.Run(method, func(t *testing.T) {
			c := queueClients(t, map[string]int{"Global": 1, "MaxPending": 2}, WorkloadAPIRateLimitConfig{})
			holder := queueStart(t, c, "FetchJWTBundles", 3, 30*time.Second)
			queueAdmitted(t, c, holder)
			failed := queueStart(t, c, method, 1, 30*time.Second)
			waitQueueStats(t, c, 1, 1)
			next := queueStart(t, c, "StreamSecrets", 7, 30*time.Second)
			waitQueueStats(t, c, 1, 2)
			c.manager.mu.Lock()
			c.manager.subscribeFailures = 1
			c.manager.mu.Unlock()
			queueStop(t, c, holder, true)
			expectStreamError(t, failed.result, codes.Unavailable)
			failed.cancel()
			queueAdmitted(t, c, next)
			waitQueueStats(t, c, 1, 0)
			queueStop(t, c, next, true)
			waitQueueStats(t, c, 0, 0)
		})
	}
}

func TestActiveStreamLimitsQueueRateAndAttestation(t *testing.T) {
	previous := perCallerRateLimiterOpts
	perCallerRateLimiterOpts = []ratelimit.Option{ratelimit.WithClock(testclock.NewMock(t))}
	t.Cleanup(func() { perCallerRateLimiterOpts = previous })
	for _, method := range policyMethods {
		t.Run(method, func(t *testing.T) {
			var rate WorkloadAPIRateLimitConfig
			reflect.ValueOf(&rate).Elem().FieldByName(method).SetInt(1)
			c := queueClients(t, map[string]int{"Global": 1, "MaxPending": 1}, rate)
			holder := queueStart(t, c, method, 3, 30*time.Second)
			queueAdmitted(t, c, holder)
			waiting := queueStart(t, c, method, 1, 30*time.Second)
			waitQueueStats(t, c, 1, 1)
			denied := queueStart(t, c, method, 2, 30*time.Second)
			expectStreamError(t, denied.result, codes.Unavailable)
			denied.cancel()
			unattested := queueStart(t, c, method, 6, 30*time.Second)
			expectStreamError(t, unattested.result, codes.Unavailable)
			unattested.cancel()
			waitQueueStats(t, c, 1, 1)
			require.Empty(t, streamLimitRejectionMetrics(c.metrics.AllMetrics(), method))
			queueStop(t, c, holder, true)
			queueAdmitted(t, c, waiting)
			queueStop(t, c, waiting, true)
			waitQueueStats(t, c, 0, 0)
		})
	}
}

func TestActiveStreamLimitsQueueStatsIsolationAndHealth(t *testing.T) {
	c := queueClients(t, map[string]int{"Global": 1, "MaxPending": 1}, WorkloadAPIRateLimitConfig{})
	other := queueClients(t, nil, WorkloadAPIRateLimitConfig{})
	a, p := queueStats(t, c)
	require.Zero(t, a)
	require.Zero(t, p)
	holder := queueStart(t, c, "FetchJWTBundles", 1, 30*time.Second)
	queueAdmitted(t, c, holder)
	pending := queueStart(t, c, "StreamSecrets", 0, 30*time.Second)
	waitQueueStats(t, c, 1, 1)
	health := queueStart(t, c, "FetchX509SVID", 0, 30*time.Second)
	queueAdmitted(t, c, health)
	waitQueueStats(t, c, 1, 1)
	unlimited := queueStart(t, other, "FetchJWTBundles", 1, 30*time.Second)
	queueAdmitted(t, other, unlimited)
	waitQueueStats(t, other, 1, 0)
	require.NoError(t, replaceStreamPolicy(t, c, map[string]int{"MaxPending": 1}))
	queueAdmitted(t, c, pending)
	waitQueueStats(t, c, 2, 0)
	queueStop(t, c, health, true)
	waitQueueStats(t, c, 2, 0)
	queueStop(t, c, holder, true)
	queueStop(t, c, pending, true)
	waitQueueStats(t, c, 0, 0)
	waitQueueStats(t, other, 1, 0)
	queueStop(t, other, unlimited, true)
	waitQueueStats(t, other, 0, 0)
}

func TestActiveStreamLimitsQueueConcurrentCapacity(t *testing.T) {
	c := queueClients(t, map[string]int{"Global": 2, "MaxPending": 3}, WorkloadAPIRateLimitConfig{})
	type call struct {
		cancel context.CancelFunc
		result <-chan error
	}
	calls := make(chan call, 24)
	start := make(chan struct{})
	for i := range 24 {
		go func(i int) {
			<-start
			cancel, result := startStream(t, c, policyMethods[i%4], 1, 30*time.Second)
			calls <- call{cancel, result}
		}(i)
	}
	close(start)
	results := make(chan error, 24)
	all := make([]call, 0, 24)
	for range 24 {
		q := <-calls
		all = append(all, q)
		go func() { results <- <-q.result }()
	}
	for range 19 {
		expectStreamError(t, results, codes.ResourceExhausted)
	}
	waitQueueStats(t, c, 2, 3)
	require.NoError(t, replaceStreamPolicy(t, c, map[string]int{"Global": 1, "MaxPending": 3}))
	a, p := queueStats(t, c)
	require.Equal(t, 2, a)
	require.Equal(t, 3, p)
	var wg sync.WaitGroup
	for _, q := range all {
		wg.Go(func() { ; q.cancel() })
	}
	wg.Wait()
	for range 5 {
		expectStreamError(t, results, codes.Canceled)
	}
	waitQueueStats(t, c, 0, 0)
	c.manager.mu.Lock()
	maximum := c.manager.maxActive
	c.manager.mu.Unlock()
	require.LessOrEqual(t, maximum, 2)
}

type queueCountingAttestor struct {
	streamTestAttestor
	mu    sync.Mutex
	calls map[int]int
}

func (a *queueCountingAttestor) Attest(ctx context.Context, pid int) ([]*common.Selector, error) {
	a.mu.Lock()
	a.calls[pid]++
	a.mu.Unlock()
	return a.streamTestAttestor.Attest(ctx, pid)
}
func TestActiveStreamLimitsQueueAttestsOnce(t *testing.T) {
	for _, method := range policyMethods {
		t.Run(method, func(t *testing.T) {
			attestor := &queueCountingAttestor{calls: make(map[int]int)}
			c := queueClients(t, map[string]int{"Global": 1, "MaxPending": 1}, WorkloadAPIRateLimitConfig{}, func(config *Config) { config.Attestor = attestor })
			holder := queueStart(t, c, "FetchJWTBundles", 3, 30*time.Second)
			queueAdmitted(t, c, holder)
			waiting := queueStart(t, c, method, 1, 30*time.Second)
			waitQueueStats(t, c, 1, 1)
			queueStop(t, c, holder, true)
			queueAdmitted(t, c, waiting)
			queueStop(t, c, waiting, true)
			attestor.mu.Lock()
			calls := attestor.calls[os.Getpid()+1]
			attestor.mu.Unlock()
			require.Equal(t, 1, calls, "waiting must preserve the original attestation")
		})
	}
}

func TestActiveStreamLimitsQueueCeilingUpdates(t *testing.T) {
	for _, field := range append([]string{"Global", "PerWorkload"}, policyMethods...) {
		t.Run(field, func(t *testing.T) {
			method := field
			if field == "Global" || field == "PerWorkload" {
				method = "FetchJWTBundles"
			}
			c := queueClients(t, map[string]int{field: 1, "MaxPending": 2}, WorkloadAPIRateLimitConfig{})
			first := queueStart(t, c, method, 1, 30*time.Second)
			queueAdmitted(t, c, first)
			second := queueStart(t, c, method, 2, 30*time.Second)
			waitQueueStats(t, c, 1, 1)
			require.NoError(t, replaceStreamPolicy(t, c, map[string]int{field: 2, "MaxPending": 2}))
			queueAdmitted(t, c, second)
			waitQueueStats(t, c, 2, 0)
			require.NoError(t, replaceStreamPolicy(t, c, map[string]int{field: 1, "MaxPending": 2}))
			third := queueStart(t, c, method, 1, 30*time.Second)
			waitQueueStats(t, c, 2, 1)
			queueStop(t, c, first, true)
			waitQueueStats(t, c, 1, 1)
			queueStop(t, c, second, true)
			queueAdmitted(t, c, third)
			queueStop(t, c, third, true)
			waitQueueStats(t, c, 0, 0)
		})
	}
}

func TestActiveStreamLimitsQueueStartupRepair(t *testing.T) {
	for _, attempt := range []bool{false, true} {
		t.Run(fmt.Sprint(attempt), func(t *testing.T) {
			c, _ := startupStreamClients(t, map[string]int{"MaxPending": -1})
			c.manager.subscribedIDs = make(chan string, 64)
			if attempt {
				started, err := observeStreamStartup(t, c)
				require.False(t, started)
				require.Error(t, err)
				require.Contains(t, err.Error(), "max_pending")
			}
			require.NoError(t, replaceStreamPolicy(t, c, map[string]int{"Global": 1, "MaxPending": 1}))
			started, err := observeStreamStartup(t, c)
			require.NoError(t, err)
			require.True(t, started)
			holder := queueStart(t, c, "FetchJWTBundles", 1, 30*time.Second)
			queueAdmitted(t, c, holder)
			waiting := queueStart(t, c, "StreamSecrets", 3, 30*time.Second)
			waitQueueStats(t, c, 1, 1)
			queueStop(t, c, holder, true)
			queueAdmitted(t, c, waiting)
			queueStop(t, c, waiting, true)
			waitQueueStats(t, c, 0, 0)
		})
	}
}

func TestActiveStreamLimitsQueueStatsTransitions(t *testing.T) {
	// Every call stays alive during observation. Policy updates only move
	// pending calls into active reservations, so their sum must be conserved.
	const waiters = 24
	const readers = 8
	for round := range 8 {
		t.Run(strconv.Itoa(round), func(t *testing.T) {
			c := queueClients(t, map[string]int{"Global": 1, "MaxPending": waiters}, WorkloadAPIRateLimitConfig{})
			holder := queueStart(t, c, "FetchJWTBundles", 1, 30*time.Second)
			queueAdmitted(t, c, holder)
			waiting := make([]queueCall, 0, waiters)
			for i := range waiters {
				waiting = append(waiting, queueStart(t, c, policyMethods[i%4], 3, 30*time.Second))
				waitQueueStats(t, c, 1, i+1)
			}
			stats := reflect.ValueOf(c.endpoint).MethodByName("WorkloadAPIStreamStats")
			type observation struct {
				samples int
				active  int
				pending int
				invalid bool
			}
			observed := make(chan observation, readers)
			stop := make(chan struct{})
			var ready, finished sync.WaitGroup
			ready.Add(readers)
			finished.Add(readers)
			for range readers {
				go func() {
					defer finished.Done()
					o := observation{}
					defer func() { observed <- o }()
					for {
						snapshot := stats.Call(nil)[0]
						a := int(snapshot.FieldByName("Active").Int())
						p := int(snapshot.FieldByName("Pending").Int())
						o.samples++
						if o.samples == 1 {
							ready.Done()
						}
						if a < 1 || a > waiters+1 || p < 0 || p > waiters || a+p != waiters+1 {
							o.active, o.pending, o.invalid = a, p, true
							return
						}
						select {
						case <-stop:
							return
						default:
							runtime.Gosched()
						}
					}
				}()
			}
			var stopOnce sync.Once
			stopReaders := func() { stopOnce.Do(func() { close(stop) }); finished.Wait() }
			defer stopReaders()
			ready.Wait()
			for ceiling := 2; ceiling <= waiters+1; ceiling++ {
				require.NoError(t, replaceStreamPolicy(t, c, map[string]int{"Global": ceiling, "MaxPending": waiters}))
				runtime.Gosched()
			}
			stopReaders()
			for range readers {
				o := <-observed
				require.Positive(t, o.samples)
				require.False(t, o.invalid, "inconsistent snapshot: active=%d pending=%d, fixed call count=%d", o.active, o.pending, waiters+1)
			}
			queueAdmitted(t, c, waiting...)
			waitQueueStats(t, c, waiters+1, 0)
			queueStop(t, c, holder, true)
			for _, call := range waiting {
				queueStop(t, c, call, true)
			}
			waitQueueStats(t, c, 0, 0)
		})
	}
}

type queueGatedAttestor struct {
	streamTestAttestor
	caller  int
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (a *queueGatedAttestor) Attest(ctx context.Context, pid int) ([]*common.Selector, error) {
	if pid == a.caller {
		a.once.Do(func() { close(a.entered) })
		select {
		case <-a.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return a.streamTestAttestor.Attest(ctx, pid)
}

func TestActiveStreamLimitsQueueAdmissionOrder(t *testing.T) {
	for i, method := range policyMethods {
		t.Run(method, func(t *testing.T) {
			attestor := &queueGatedAttestor{caller: os.Getpid() + 3, entered: make(chan struct{}), release: make(chan struct{})}
			var once sync.Once
			unblock := func() { once.Do(func() { close(attestor.release) }) }
			defer unblock()
			c := queueClients(t, map[string]int{"Global": 1, "MaxPending": 2}, WorkloadAPIRateLimitConfig{}, func(config *Config) { config.Attestor = attestor })
			holder := queueStart(t, c, "FetchJWTBundles", 1, 30*time.Second)
			queueAdmitted(t, c, holder)
			earlierRPC := queueStart(t, c, method, 3, 30*time.Second)
			select {
			case <-attestor.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("earlier RPC did not reach attestation")
			}
			// This RPC starts later but reaches the admission decision first.
			firstWaiter := queueStart(t, c, policyMethods[(i+1)%4], 7, 30*time.Second)
			waitQueueStats(t, c, 1, 1)
			unblock()
			waitQueueStats(t, c, 1, 2)
			queueStop(t, c, holder, true)
			queueAdmitted(t, c, firstWaiter)
			waitQueueStats(t, c, 1, 1)
			queueStop(t, c, firstWaiter, true)
			queueAdmitted(t, c, earlierRPC)
			queueStop(t, c, earlierRPC, true)
			waitQueueStats(t, c, 0, 0)
		})
	}
}
