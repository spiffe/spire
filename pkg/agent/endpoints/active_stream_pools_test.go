package endpoints

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type poolCase struct {
	name      string
	selectors []string
	limit     int
}

func poolPolicy(t *testing.T, limits map[string]int, pools ...poolCase) reflect.Value {
	t.Helper()
	field, ok := reflect.TypeFor[Config]().FieldByName("WorkloadAPIStreamLimits")
	require.True(t, ok)
	p := reflect.New(field.Type).Elem()
	for key, value := range limits {
		p.FieldByName(key).SetInt(int64(value))
	}
	ps := p.FieldByName("Pools")
	require.True(t, ps.IsValid(), "stream policy must expose selector pools")
	require.Equal(t, reflect.Slice, ps.Kind())
	ps.Set(reflect.MakeSlice(ps.Type(), len(pools), len(pools)))
	for i, pool := range pools {
		item := ps.Index(i)
		require.Equal(t, reflect.Struct, item.Kind())
		for _, key := range []string{"Name", "Selectors", "Limit"} {
			require.True(t, item.FieldByName(key).IsValid(), "pool must expose %s", key)
		}
		item.FieldByName("Name").SetString(pool.name)
		item.FieldByName("Selectors").Set(reflect.ValueOf(append([]string(nil), pool.selectors...)))
		item.FieldByName("Limit").SetInt(int64(pool.limit))
	}
	return p
}

func poolClients(t *testing.T, p reflect.Value, options ...func(*Config)) streamTestClients {
	t.Helper()
	return queueClients(t, nil, WorkloadAPIRateLimitConfig{}, append(options, func(c *Config) { reflect.ValueOf(c).Elem().FieldByName("WorkloadAPIStreamLimits").Set(p) })...)
}

func poolReplace(t *testing.T, c streamTestClients, p reflect.Value) error {
	t.Helper()
	result := reflect.ValueOf(c.endpoint).MethodByName("UpdateWorkloadAPIStreamLimits").Call([]reflect.Value{p})[0]
	if result.IsNil() {
		return nil
	}
	return result.Interface().(error)
}

func poolSnapshot(t *testing.T, c streamTestClients) (int, int, map[string]int) {
	t.Helper()
	s := reflect.ValueOf(c.endpoint).MethodByName("WorkloadAPIStreamStats").Call(nil)[0]
	field := s.FieldByName("PoolActive")
	require.True(t, field.IsValid(), "stats must expose PoolActive")
	counts, ok := reflect.TypeAssert[map[string]int](field)
	require.True(t, ok, "PoolActive must be map[string]int")
	return int(s.FieldByName("Active").Int()), int(s.FieldByName("Pending").Int()), counts
}

func poolCounts(t *testing.T, c streamTestClients, active, pending int, pools map[string]int) {
	t.Helper()
	a, p, got := poolSnapshot(t, c)
	require.Equal(t, active, a)
	require.Equal(t, pending, p)
	require.Equal(t, pools, got)
}

func TestActiveStreamLimitsPoolMembership(t *testing.T) {
	cases := []struct {
		name                        string
		selectors                   []string
		holder, probe               int
		matchesHolder, matchesProbe bool
	}{
		{"subset", []string{"k8s:ns:shared"}, 1, 7, true, true},
		{"order_and_duplicates", []string{"unix:uid:1000", "k8s:ns:shared", "unix:uid:1000"}, 7, 8, true, true},
		{"conjunction", []string{"k8s:ns:shared", "unix:uid:1000"}, 7, 1, true, false},
		{"type_boundary", []string{"unix:same-value"}, 9, 10, true, false},
		{"value_boundary", []string{"k8s:ns:shared"}, 1, 3, true, false},
		{"colon_value", []string{"unix:uid:1000"}, 7, 8, true, true},
		{"empty_matches_all", nil, 4, 5, true, true},
		{"no_selectors_no_match", []string{"k8s:ns:shared"}, 4, 5, false, false},
	}
	for _, tc := range cases {
		for i, method := range policyMethods {
			t.Run(tc.name+"/"+method, func(t *testing.T) {
				c := poolClients(t, poolPolicy(t, nil, poolCase{"tenant", tc.selectors, 1}))
				holder := queueStart(t, c, method, tc.holder, 30*time.Second)
				queueAdmitted(t, c, holder)
				want := 0
				if tc.matchesHolder {
					want++
				}
				poolCounts(t, c, 1, 0, map[string]int{"tenant": want})
				probe := queueStart(t, c, policyMethods[(i+1)%4], tc.probe, 30*time.Second)
				if tc.matchesHolder && tc.matchesProbe {
					expectStreamError(t, probe.result, codes.ResourceExhausted)
					rejectedMethod := policyMethods[(i+1)%4]
					metrics := streamLimitRejectionMetrics(c.metrics.AllMetrics(), rejectedMethod)
					require.Len(t, metrics, 1)
					require.Equal(t, float64(1), metrics[0].Val)
					require.Len(t, metrics[0].Labels, 1)
					require.Equal(t, "method", metrics[0].Labels[0].Name)
					require.NotEqual(t, []string{"workload_api", "rate_limit_exceeded"}, metrics[0].Key)
					probe.cancel()
				} else {
					queueAdmitted(t, c, probe)
					if tc.matchesProbe {
						want++
					}
					poolCounts(t, c, 2, 0, map[string]int{"tenant": want})
					queueStop(t, c, probe, true)
				}
				queueStop(t, c, holder, true)
				poolCounts(t, c, 0, 0, map[string]int{"tenant": 0})
			})
		}
	}
}

func TestActiveStreamLimitsPoolOverlappingReservation(t *testing.T) {
	for _, method := range policyMethods {
		t.Run(method, func(t *testing.T) {
			c := poolClients(t, poolPolicy(t, nil, poolCase{"namespace", []string{"k8s:ns:shared"}, 2}, poolCase{"user", []string{"unix:uid:1000"}, 1}, poolCase{"unlimited", nil, 0}))
			a := queueStart(t, c, method, 7, 30*time.Second)
			queueAdmitted(t, c, a)
			denyLifecycleStream(t, c, method, 8)
			b := queueStart(t, c, "StreamSecrets", 1, 30*time.Second)
			queueAdmitted(t, c, b)
			poolCounts(t, c, 2, 0, map[string]int{"namespace": 2, "user": 1, "unlimited": 2})
			denyLifecycleStream(t, c, "FetchJWTBundles", 2)
			queueStop(t, c, a, true)
			d := queueStart(t, c, "FetchX509Bundles", 8, 30*time.Second)
			queueAdmitted(t, c, d)
			poolCounts(t, c, 2, 0, map[string]int{"namespace": 2, "user": 1, "unlimited": 2})
			queueStop(t, c, b, true)
			queueStop(t, c, d, true)
			poolCounts(t, c, 0, 0, map[string]int{"namespace": 0, "user": 0, "unlimited": 0})
		})
	}
}

func TestActiveStreamLimitsPoolQueueReclassification(t *testing.T) {
	c := poolClients(t, poolPolicy(t, map[string]int{"Global": 1, "MaxPending": 3}))
	holder := queueStart(t, c, "FetchX509SVID", 1, 30*time.Second)
	queueAdmitted(t, c, holder)
	oldest := queueStart(t, c, "FetchJWTBundles", 7, 30*time.Second)
	waitQueueStats(t, c, 1, 1)
	eligible := queueStart(t, c, "StreamSecrets", 3, 30*time.Second)
	waitQueueStats(t, c, 1, 2)
	newest := queueStart(t, c, "FetchX509Bundles", 8, 30*time.Second)
	waitQueueStats(t, c, 1, 3)
	require.NoError(t, poolReplace(t, c, poolPolicy(t, map[string]int{"MaxPending": 1}, poolCase{"namespace", []string{"k8s:ns:shared"}, 1})))
	poolCounts(t, c, 2, 1, map[string]int{"namespace": 1})
	queueAdmitted(t, c, eligible)
	expectStreamError(t, newest.result, codes.ResourceExhausted)
	newest.cancel()
	metrics := streamLimitRejectionMetrics(c.metrics.AllMetrics(), "FetchX509Bundles")
	require.Len(t, metrics, 1)
	require.Equal(t, float64(1), metrics[0].Val)
	require.Len(t, metrics[0].Labels, 1)
	require.Empty(t, streamLimitRejectionMetrics(c.metrics.AllMetrics(), "FetchJWTBundles"))
	queueStop(t, c, holder, true)
	queueAdmitted(t, c, oldest)
	poolCounts(t, c, 2, 0, map[string]int{"namespace": 1})
	queueStop(t, c, oldest, true)
	queueStop(t, c, eligible, true)
	poolCounts(t, c, 0, 0, map[string]int{"namespace": 0})
}

func TestActiveStreamLimitsPoolLiveMembershipAndRelease(t *testing.T) {
	for _, variant := range []string{"new_pool", "same_name_new_rule", "renamed", "reordered"} {
		t.Run(variant, func(t *testing.T) {
			initial := []poolCase{{"ns", []string{"unix:uid:1000"}, 0}, {"other", []string{"k8s:ns:other"}, 0}}
			if variant == "new_pool" {
				initial = nil
			}
			c := poolClients(t, poolPolicy(t, nil, initial...))
			a := queueStart(t, c, "StreamSecrets", 7, 30*time.Second)
			queueAdmitted(t, c, a)
			b := queueStart(t, c, "FetchJWTBundles", 1, 30*time.Second)
			queueAdmitted(t, c, b)
			name := "ns"
			if variant == "renamed" {
				name = "replacement"
			}
			replacement := []poolCase{{name, []string{"k8s:ns:shared"}, 1}, {"other", []string{"k8s:ns:other"}, 0}}
			if variant == "reordered" {
				replacement[0], replacement[1] = replacement[1], replacement[0]
			}
			require.NoError(t, poolReplace(t, c, poolPolicy(t, map[string]int{"MaxPending": 1}, replacement...)))
			poolCounts(t, c, 2, 0, map[string]int{name: 2, "other": 0})
			waiter := queueStart(t, c, "FetchX509Bundles", 8, 30*time.Second)
			waitQueueStats(t, c, 2, 1)
			queueStop(t, c, a, true)
			poolCounts(t, c, 1, 1, map[string]int{name: 1, "other": 0})
			queueStop(t, c, b, true)
			queueAdmitted(t, c, waiter)
			poolCounts(t, c, 1, 0, map[string]int{name: 1, "other": 0})
			// Removing all rules must release waiting calls, and later release must not
			// retain or resurrect any old pool, even if a name is subsequently reused.
			next := queueStart(t, c, "StreamSecrets", 7, 30*time.Second)
			waitQueueStats(t, c, 1, 1)
			require.NoError(t, poolReplace(t, c, poolPolicy(t, nil)))
			queueAdmitted(t, c, next)
			_, _, counts := poolSnapshot(t, c)
			require.Empty(t, counts)
			require.NoError(t, poolReplace(t, c, poolPolicy(t, nil, poolCase{name, []string{"k8s:ns:other"}, 1})))
			other := queueStart(t, c, "FetchJWTBundles", 3, 30*time.Second)
			queueAdmitted(t, c, other)
			queueStop(t, c, waiter, true)
			queueStop(t, c, next, true)
			poolCounts(t, c, 1, 0, map[string]int{name: 1})
			denyLifecycleStream(t, c, "StreamSecrets", 3)
			queueStop(t, c, other, true)
			poolCounts(t, c, 0, 0, map[string]int{name: 0})
		})
	}
}

func TestActiveStreamLimitsPoolPolicyOwnership(t *testing.T) {
	for _, when := range []string{"construction", "replacement"} {
		t.Run(when, func(t *testing.T) {
			policy := poolPolicy(t, nil, poolCase{"tenant", []string{"k8s:ns:shared"}, 1})
			socket := filepath.Join(spiretest.TempDir(t), "ownership.sock")
			bind := func(config *Config) { config.BindAddr = &net.UnixAddr{Name: socket, Net: "unix"} }
			var c streamTestClients
			if when == "construction" {
				c = poolClients(t, policy, bind)
			} else {
				c = poolClients(t, poolPolicy(t, nil), bind)
				require.NoError(t, poolReplace(t, c, policy))
			}
			p := policy.FieldByName("Pools").Index(0)
			p.FieldByName("Selectors").Index(0).SetString("invalid")
			p.FieldByName("Name").SetString("changed")
			p.FieldByName("Limit").SetInt(-1)
			started, err := observeStreamStartup(t, c)
			require.NoError(t, err, "caller edits after the API returns must not change startup validation")
			require.True(t, started)
			holder := queueStart(t, c, "FetchX509Bundles", 1, 30*time.Second)
			queueAdmitted(t, c, holder)
			denyLifecycleStream(t, c, "StreamSecrets", 7)
			poolCounts(t, c, 1, 0, map[string]int{"tenant": 1})
			_, _, first := poolSnapshot(t, c)
			_, _, second := poolSnapshot(t, c)
			first["tenant"] = 888
			first["foreign"] = 1
			delete(first, "tenant")
			require.Equal(t, map[string]int{"tenant": 1}, second)
			poolCounts(t, c, 1, 0, map[string]int{"tenant": 1})
			queueStop(t, c, holder, true)
		})
	}
}

type poolMutableAttestor struct {
	streamTestAttestor
	selectors []*common.Selector
}

func (a *poolMutableAttestor) Attest(context.Context, int) ([]*common.Selector, error) {
	return a.selectors, nil
}

func TestActiveStreamLimitsPoolOriginalAttestation(t *testing.T) {
	attestor := &poolMutableAttestor{selectors: []*common.Selector{{Type: "k8s", Value: "ns:shared"}}}
	c := poolClients(t, poolPolicy(t, nil), func(config *Config) { config.Attestor = attestor })
	holder := queueStart(t, c, "StreamSecrets", 1, 30*time.Second)
	queueAdmitted(t, c, holder)
	attestor.selectors[0].Value = "ns:other"
	require.NoError(t, poolReplace(t, c, poolPolicy(t, nil, poolCase{"original", []string{"k8s:ns:shared"}, 1}, poolCase{"later", []string{"k8s:ns:other"}, 1})))
	poolCounts(t, c, 1, 0, map[string]int{"original": 1, "later": 0})
	later := queueStart(t, c, "FetchJWTBundles", 2, 30*time.Second)
	queueAdmitted(t, c, later)
	poolCounts(t, c, 2, 0, map[string]int{"original": 1, "later": 1})
	queueStop(t, c, holder, true)
	poolCounts(t, c, 1, 0, map[string]int{"original": 0, "later": 1})
	queueStop(t, c, later, true)
}

func TestActiveStreamLimitsPoolInvalidPolicyAtomicity(t *testing.T) {
	cases := []struct {
		name, key string
		pools     []poolCase
	}{
		{"empty_name", "name", []poolCase{{"", nil, 1}}},
		{"duplicate_name", "name", []poolCase{{"x", nil, 1}, {"x", []string{"unix:uid:1000"}, 1}}},
		{"negative_limit", "limit", []poolCase{{"x", nil, -1}}},
		{"no_colon", "selectors", []poolCase{{"x", []string{"unix"}, 1}}},
		{"empty_type", "selectors", []poolCase{{"x", []string{":value"}, 1}}},
		{"empty_value", "selectors", []poolCase{{"x", []string{"unix:"}, 1}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := poolClients(t, poolPolicy(t, map[string]int{"MaxPending": 2}, poolCase{"all", nil, 1}))
			holder := queueStart(t, c, "StreamSecrets", 1, 30*time.Second)
			queueAdmitted(t, c, holder)
			first := queueStart(t, c, "FetchJWTBundles", 7, 30*time.Second)
			waitQueueStats(t, c, 1, 1)
			last := queueStart(t, c, "FetchX509Bundles", 3, 30*time.Second)
			waitQueueStats(t, c, 1, 2)
			err := poolReplace(t, c, poolPolicy(t, nil, tc.pools...))
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.key)
			poolCounts(t, c, 1, 2, map[string]int{"all": 1})
			queueStop(t, c, holder, true)
			queueAdmitted(t, c, first)
			queueStop(t, c, first, true)
			queueAdmitted(t, c, last)
			queueStop(t, c, last, true)
		})
	}
}

func TestActiveStreamLimitsPoolStartupValidationAndRepair(t *testing.T) {
	for _, tc := range []struct {
		name, key string
		pools     []poolCase
	}{
		{"empty_name", "name", []poolCase{{"", nil, 1}}},
		{"duplicate_name", "name", []poolCase{{"x", nil, 1}, {"x", nil, 2}}},
		{"negative_limit", "limit", []poolCase{{"x", nil, -1}}},
		{"no_colon", "selectors", []poolCase{{"x", []string{"invalid"}, 1}}},
		{"empty_type", "selectors", []poolCase{{"x", []string{":value"}, 1}}},
		{"empty_value", "selectors", []poolCase{{"x", []string{"type:"}, 1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socket := filepath.Join(spiretest.TempDir(t), "pool.sock")
			c := poolClients(t, poolPolicy(t, nil, tc.pools...), func(config *Config) { config.BindAddr = &net.UnixAddr{Name: socket, Net: "unix"} })
			occupied, err := net.Listen("unix", socket)
			require.NoError(t, err)
			started, err := observeStreamStartup(t, c)
			require.False(t, started)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.key)
			require.NoError(t, occupied.Close())
			require.NoError(t, poolReplace(t, c, poolPolicy(t, nil, poolCase{"all", nil, 1})))
			started, err = observeStreamStartup(t, c)
			require.NoError(t, err)
			require.True(t, started)
			holder := queueStart(t, c, "StreamSecrets", 1, 30*time.Second)
			queueAdmitted(t, c, holder)
			denyLifecycleStream(t, c, "FetchX509Bundles", 3)
			queueStop(t, c, holder, true)
		})
	}
}

func TestActiveStreamLimitsPoolCancellationAndHealth(t *testing.T) {
	for _, method := range policyMethods {
		t.Run(method, func(t *testing.T) {
			c := poolClients(t, poolPolicy(t, map[string]int{"MaxPending": 1}, poolCase{"all", nil, 1}))
			holder := queueStart(t, c, method, 1, 30*time.Second)
			queueAdmitted(t, c, holder)
			waiter := queueStart(t, c, "StreamSecrets", 3, 30*time.Second)
			waitQueueStats(t, c, 1, 1)
			queueStop(t, c, waiter, false)
			poolCounts(t, c, 1, 0, map[string]int{"all": 1})
			health := queueStart(t, c, "FetchX509SVID", 0, 30*time.Second)
			queueAdmitted(t, c, health)
			poolCounts(t, c, 1, 0, map[string]int{"all": 1})
			queueStop(t, c, health, true)
			deadline := queueStart(t, c, "FetchJWTBundles", 3, 60*time.Millisecond)
			expectStreamError(t, deadline.result, codes.DeadlineExceeded)
			deadline.cancel()
			waitQueueStats(t, c, 1, 0)
			require.Empty(t, streamLimitRejectionMetrics(c.metrics.AllMetrics(), "FetchJWTBundles"))
			next := queueStart(t, c, "StreamSecrets", 3, 30*time.Second)
			waitQueueStats(t, c, 1, 1)
			queueStop(t, c, holder, true)
			queueAdmitted(t, c, next)
			queueStop(t, c, next, true)
			poolCounts(t, c, 0, 0, map[string]int{"all": 0})
		})
	}
}

func TestActiveStreamLimitsPoolStatsCoherence(t *testing.T) {
	c := poolClients(t, poolPolicy(t, map[string]int{"MaxPending": 24}, poolCase{"a", nil, 1}, poolCase{"b", nil, 1}))
	calls := []queueCall{queueStart(t, c, "StreamSecrets", 1, 30*time.Second)}
	queueAdmitted(t, c, calls[0])
	for i := range 24 {
		calls = append(calls, queueStart(t, c, policyMethods[i%4], 1+(i%2)*2, 30*time.Second))
	}
	waitQueueStats(t, c, 1, 24)
	var readers sync.WaitGroup
	stop := make(chan struct{})
	bad := make(chan string, 1)
	for range 8 {
		readers.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				a, p, counts := poolSnapshot(t, c)
				if len(counts) != 2 || counts["a"] != a || counts["b"] != a || a+p != 25 {
					select {
					case bad <- fmt.Sprintf("active=%d pending=%d pools=%v", a, p, counts):
					default:
					}
					return
				}
			}
		})
	}
	for limit := 2; limit <= 25; limit++ {
		require.NoError(t, poolReplace(t, c, poolPolicy(t, map[string]int{"MaxPending": 24}, poolCase{"b", nil, limit}, poolCase{"a", nil, limit})))
	}
	close(stop)
	readers.Wait()
	select {
	case message := <-bad:
		t.Fatal(message)
	default:
	}
	queueAdmitted(t, c, calls[1:]...)
	poolCounts(t, c, 25, 0, map[string]int{"a": 25, "b": 25})
	for _, call := range calls {
		queueStop(t, c, call, true)
	}
	poolCounts(t, c, 0, 0, map[string]int{"a": 0, "b": 0})
}

func TestActiveStreamLimitsPoolInstancesIndependent(t *testing.T) {
	p := poolPolicy(t, nil, poolCase{"tenant", nil, 1})
	a, b := poolClients(t, p), poolClients(t, p)
	first := queueStart(t, a, "FetchJWTBundles", 1, 30*time.Second)
	queueAdmitted(t, a, first)
	second := queueStart(t, b, "StreamSecrets", 1, 30*time.Second)
	queueAdmitted(t, b, second)
	require.NoError(t, poolReplace(t, a, poolPolicy(t, nil, poolCase{"changed", nil, 2})))
	poolCounts(t, b, 1, 0, map[string]int{"tenant": 1})
	denyLifecycleStream(t, b, "FetchX509Bundles", 1)
	queueStop(t, a, first, true)
	queueStop(t, b, second, true)
}

type poolBarrierAttestor struct {
	streamTestAttestor
	entered chan struct{}
	proceed <-chan struct{}
}

func (a *poolBarrierAttestor) Attest(ctx context.Context, pid int) ([]*common.Selector, error) {
	selectors, err := a.streamTestAttestor.Attest(ctx, pid)
	a.entered <- struct{}{}
	select {
	case <-a.proceed:
		return selectors, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestActiveStreamLimitsPoolConcurrentReservations(t *testing.T) {
	proceed := make(chan struct{})
	attestor := &poolBarrierAttestor{entered: make(chan struct{}, 32), proceed: proceed}
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(proceed) }) })
	c := poolClients(t, poolPolicy(t, nil, poolCase{"tenant", []string{"k8s:ns:shared"}, 5}, poolCase{"overlap", nil, 7}), func(config *Config) { config.Attestor = attestor })
	calls := make([]queueCall, 32)
	cases := make([]reflect.SelectCase, 32)
	for i := range calls {
		cancel, result := startStream(t, c, policyMethods[i%4], 1+(i%2)*6, 30*time.Second)
		calls[i] = queueCall{cancel: cancel, result: result}
		cases[i] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(result)}
	}
	for range calls {
		waitStreamEvent(t, attestor.entered, "attested stream")
	}
	once.Do(func() { close(proceed) })
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	cases = append(cases, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(timeout.C)})
	denied := make(map[int]bool)
	for range 27 {
		selected, value, _ := reflect.Select(cases)
		require.Less(t, selected, 32, "every stream beyond the pool ceiling must be rejected")
		require.Equal(t, codes.ResourceExhausted, status.Code(value.Interface().(error)))
		denied[selected] = true
		cases[selected].Chan = reflect.Value{}
	}
	for range 5 {
		waitStreamEvent(t, c.manager.started, "admitted stream")
	}
	poolCounts(t, c, 5, 0, map[string]int{"tenant": 5, "overlap": 5})
	for i, call := range calls {
		call.cancel()
		if !denied[i] {
			expectStreamError(t, call.result, codes.Canceled)
		}
	}
	poolCounts(t, c, 0, 0, map[string]int{"tenant": 0, "overlap": 0})
}

func TestActiveStreamLimitsPoolAdmissionErrorHandoff(t *testing.T) {
	c := poolClients(t, poolPolicy(t, map[string]int{"MaxPending": 2}, poolCase{"tenant", nil, 1}))
	holder := queueStart(t, c, "FetchX509SVID", 1, 30*time.Second)
	queueAdmitted(t, c, holder)
	first := queueStart(t, c, "StreamSecrets", 3, 30*time.Second)
	waitQueueStats(t, c, 1, 1)
	last := queueStart(t, c, "FetchJWTBundles", 7, 30*time.Second)
	waitQueueStats(t, c, 1, 2)
	c.manager.mu.Lock()
	c.manager.subscribeFailures = 1
	c.manager.mu.Unlock()
	queueStop(t, c, holder, true)
	expectStreamError(t, first.result, codes.Unavailable)
	first.cancel()
	queueAdmitted(t, c, last)
	poolCounts(t, c, 1, 0, map[string]int{"tenant": 1})
	require.Empty(t, streamLimitRejectionMetrics(c.metrics.AllMetrics(), "StreamSecrets"))
	queueStop(t, c, last, true)
	poolCounts(t, c, 0, 0, map[string]int{"tenant": 0})
}

func TestActiveStreamLimitsPoolComposesWithExistingCeilings(t *testing.T) {
	for _, method := range policyMethods {
		for _, scope := range []string{method, "PerWorkload", "Global"} {
			t.Run(method+"/"+scope, func(t *testing.T) {
				c := poolClients(t, poolPolicy(t, map[string]int{scope: 1}, poolCase{"all", nil, 9}))
				holder := queueStart(t, c, method, 1, 30*time.Second)
				queueAdmitted(t, c, holder)
				next, caller := method, 2
				if scope == "PerWorkload" {
					if method == "StreamSecrets" {
						next = "FetchJWTBundles"
					} else {
						next = "StreamSecrets"
					}
				}
				if scope == "Global" {
					caller = 3
				}
				denyLifecycleStream(t, c, next, caller)
				poolCounts(t, c, 1, 0, map[string]int{"all": 1})
				queueStop(t, c, holder, true)
			})
		}
	}
}
