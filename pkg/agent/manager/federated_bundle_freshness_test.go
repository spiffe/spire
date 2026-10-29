package manager

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/agent/manager/storecache"
	agentsvid "github.com/spiffe/spire/pkg/agent/svid"
	"github.com/spiffe/spire/pkg/agent/workloadkey"
	"github.com/spiffe/spire/pkg/common/errorutil"
	"github.com/spiffe/spire/pkg/common/rotationutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakeagentcatalog"
	"github.com/spiffe/spire/test/fakes/fakeagentkeymanager"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

const testFreshnessLimit = 3 * time.Second

type freshnessResponseFn func(int32) (*entryv1.GetAuthorizedEntriesResponse, error)

func TestFederatedBundleFreshnessManager(t *testing.T) {
	t.Run("expires_at_limit_and_notifies_bundle_stream", func(t *testing.T) {
		m, clk, remoteTD := newFreshnessManagerWithEntries(t, testFreshnessLimit, nil, nil, "resp3", "resp4")
		stream := m.SubscribeToBundleChanges()
		require.Contains(t, stream.Value(), remoteTD)
		require.Equal(t, m.GetBundles(), stream.Value())
		beforeWorkload := m.FetchWorkloadUpdate(regEntriesMap["resp3"][0].Selectors)
		require.NotEmpty(t, beforeWorkload.Identities)
		beforeStored := m.svidStoreCache.Records()
		require.NotEmpty(t, beforeStored)
		stop := runManager(t, m)
		defer stop()

		clk.Add(testFreshnessLimit - time.Nanosecond)
		require.Contains(t, m.GetBundles(), remoteTD)

		clk.Add(time.Nanosecond)
		require.Eventually(t, func() bool {
			_, ok := m.GetBundles()[remoteTD]
			return !ok
		}, 2*time.Second, 10*time.Millisecond)
		require.Eventually(t, stream.HasNext, 2*time.Second, 10*time.Millisecond)
		require.Equal(t, m.GetBundles(), stream.Next())
		require.Contains(t, m.GetBundles(), trustDomain)

		afterWorkload := m.FetchWorkloadUpdate(regEntriesMap["resp3"][0].Selectors)
		require.Equal(t, beforeWorkload.Identities, afterWorkload.Identities)
		afterStored := m.svidStoreCache.Records()
		require.Len(t, afterStored, len(beforeStored))
		for i := range beforeStored {
			require.Equal(t, beforeStored[i].ID, afterStored[i].ID)
			require.Equal(t, beforeStored[i].Entry, afterStored[i].Entry)
			require.Equal(t, beforeStored[i].ExpiresAt, afterStored[i].ExpiresAt)
			require.Equal(t, beforeStored[i].Svid, afterStored[i].Svid)
		}
	})

	t.Run("successful_sync_refreshes_and_readmits", func(t *testing.T) {
		m, clk, remoteTD := newFreshnessManager(t, testFreshnessLimit, nil, nil)
		stream := m.SubscribeToBundleChanges()
		stop := runManager(t, m)
		defer stop()

		clk.Add(testFreshnessLimit / 2)
		require.NoError(t, m.synchronize(context.Background()))
		clk.Add(testFreshnessLimit / 2)
		require.Contains(t, m.GetBundles(), remoteTD)

		clk.Add(testFreshnessLimit / 2)
		require.Eventually(t, func() bool {
			_, ok := m.GetBundles()[remoteTD]
			return !ok
		}, 2*time.Second, 10*time.Millisecond)
		require.Eventually(t, stream.HasNext, 2*time.Second, 10*time.Millisecond)
		require.Equal(t, m.GetBundles(), stream.Next())

		require.NoError(t, m.synchronize(context.Background()))
		require.Contains(t, m.GetBundles(), remoteTD)
		require.Eventually(t, stream.HasNext, 2*time.Second, 10*time.Millisecond)
		require.Equal(t, m.GetBundles(), stream.Next())
	})

	t.Run("failed_sync_does_not_refresh", func(t *testing.T) {
		responses := func(count int32) (*entryv1.GetAuthorizedEntriesResponse, error) {
			if count > 1 {
				return nil, errors.New("intentional synchronization failure")
			}
			return makeGetAuthorizedEntriesResponse(t, "resp3"), nil
		}
		m, clk, remoteTD := newFreshnessManager(t, testFreshnessLimit, nil, responses)
		stop := runManager(t, m)
		defer stop()

		clk.Add(testFreshnessLimit / 2)
		require.Error(t, m.synchronize(context.Background()))
		clk.Add(testFreshnessLimit / 2)
		require.Eventually(t, func() bool {
			_, ok := m.GetBundles()[remoteTD]
			return !ok
		}, 2*time.Second, 10*time.Millisecond)
	})

	t.Run("failed_svid_update_does_not_refresh", func(t *testing.T) {
		responses := func(count int32) (*entryv1.GetAuthorizedEntriesResponse, error) {
			response := makeGetAuthorizedEntriesResponse(t, "resp3")
			if count > 1 {
				response.Entries[0].Id += "-replacement"
			}
			return response, nil
		}
		m, clk, remoteTD := newFreshnessManager(t, testFreshnessLimit, nil, responses)
		m.c.WorkloadKeyType = workloadkey.KeyTypeUnset
		stop := runManager(t, m)
		defer stop()

		clk.Add(testFreshnessLimit / 2)
		require.Error(t, m.synchronize(context.Background()))
		clk.Add(testFreshnessLimit / 2)
		require.Eventually(t, func() bool {
			_, ok := m.GetBundles()[remoteTD]
			return !ok
		}, 2*time.Second, 10*time.Millisecond)
	})

	t.Run("failed_svid_update_still_removes_omitted_bundle", func(t *testing.T) {
		responses := func(count int32) (*entryv1.GetAuthorizedEntriesResponse, error) {
			response := makeGetAuthorizedEntriesResponse(t, "resp3")
			if count > 1 {
				response.Entries[0].Id += "-replacement"
				for _, entry := range response.Entries {
					entry.FederatesWith = nil
				}
			}
			return response, nil
		}
		metrics := fakemetrics.New()
		m, _, remoteTD := newFreshnessManager(t, time.Hour, metrics, responses)
		stream := m.SubscribeToBundleChanges()
		m.c.WorkloadKeyType = workloadkey.KeyTypeUnset

		require.Error(t, m.synchronize(context.Background()))
		require.NotContains(t, m.GetBundles(), remoteTD)
		require.True(t, stream.HasNext())
		require.Equal(t, m.GetBundles(), stream.Next())
		require.Contains(t, m.GetBundles(), trustDomain)
		requireMetric(t, metrics, fakemetrics.SetGaugeType, "fresh", 0)
		requireMetric(t, metrics, fakemetrics.SetGaugeType, "stale", 0)
		require.Zero(t, metricTotal(metrics, "expiry"))
		require.Zero(t, metricTotal(metrics, "readmission"))
	})

	t.Run("expires_while_manager_reattests", func(t *testing.T) {
		m, clk, remoteTD := newFreshnessManager(t, testFreshnessLimit, nil, nil)
		stream := m.SubscribeToBundleChanges()
		reattest := &heldReattestation{
			Rotator: m.svid,
			entered: make(chan struct{}, 1),
			release: make(chan struct{}),
		}
		m.svid = reattest

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- m.Run(ctx) }()
		defer func() {
			cancel()
			close(reattest.release)
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("manager did not stop after cancellation")
			}
		}()

		select {
		case <-reattest.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("manager did not enter re-attestation")
		}
		clk.Add(testFreshnessLimit)
		require.Eventually(t, func() bool {
			_, visible := m.GetBundles()[remoteTD]
			return !visible
		}, 2*time.Second, 10*time.Millisecond)
		require.Eventually(t, stream.HasNext, 2*time.Second, 10*time.Millisecond)
		require.Equal(t, m.GetBundles(), stream.Next())
		require.Contains(t, m.GetBundles(), trustDomain)
	})

	t.Run("successful_omission_is_immediate", func(t *testing.T) {
		responses := func(count int32) (*entryv1.GetAuthorizedEntriesResponse, error) {
			if count == 2 {
				return new(entryv1.GetAuthorizedEntriesResponse), nil
			}
			return makeGetAuthorizedEntriesResponse(t, "resp3"), nil
		}
		metrics := fakemetrics.New()
		m, _, remoteTD := newFreshnessManager(t, time.Hour, metrics, responses)
		stream := m.SubscribeToBundleChanges()
		require.Contains(t, stream.Value(), remoteTD)
		require.Equal(t, m.GetBundles(), stream.Value())
		requireMetric(t, metrics, fakemetrics.SetGaugeType, "fresh", 1)
		requireMetric(t, metrics, fakemetrics.SetGaugeType, "stale", 0)

		require.NoError(t, m.synchronize(context.Background()))
		require.NotContains(t, m.GetBundles(), remoteTD)
		require.True(t, stream.HasNext())
		require.Equal(t, m.GetBundles(), stream.Next())
		requireMetric(t, metrics, fakemetrics.SetGaugeType, "fresh", 0)
		requireMetric(t, metrics, fakemetrics.SetGaugeType, "stale", 0)
		require.Zero(t, metricTotal(metrics, "expiry"))
		require.Zero(t, metricTotal(metrics, "readmission"))

		require.NoError(t, m.synchronize(context.Background()))
		require.Contains(t, m.GetBundles(), remoteTD)
		require.True(t, stream.HasNext())
		require.Equal(t, m.GetBundles(), stream.Next())
		requireMetric(t, metrics, fakemetrics.SetGaugeType, "fresh", 1)
		requireMetric(t, metrics, fakemetrics.SetGaugeType, "stale", 0)
		require.Zero(t, metricTotal(metrics, "expiry"))
		require.Zero(t, metricTotal(metrics, "readmission"))
	})

	t.Run("omitting_stale_bundle_does_not_readmit", func(t *testing.T) {
		responses := func(count int32) (*entryv1.GetAuthorizedEntriesResponse, error) {
			if count > 1 {
				return new(entryv1.GetAuthorizedEntriesResponse), nil
			}
			return makeGetAuthorizedEntriesResponse(t, "resp3"), nil
		}
		metrics := fakemetrics.New()
		m, clk, remoteTD := newFreshnessManager(t, testFreshnessLimit, metrics, responses)
		stop := runManager(t, m)
		defer stop()

		clk.Add(testFreshnessLimit)
		require.Eventually(t, func() bool {
			_, visible := m.GetBundles()[remoteTD]
			return !visible
		}, 2*time.Second, 10*time.Millisecond)
		requireMetric(t, metrics, fakemetrics.SetGaugeType, "fresh", 0)
		requireMetric(t, metrics, fakemetrics.SetGaugeType, "stale", 1)
		require.Equal(t, float64(1), metricTotal(metrics, "expiry"))
		require.Zero(t, metricTotal(metrics, "readmission"))

		require.NoError(t, m.synchronize(context.Background()))
		require.NotContains(t, m.GetBundles(), remoteTD)
		require.Contains(t, m.GetBundles(), trustDomain)
		requireMetric(t, metrics, fakemetrics.SetGaugeType, "fresh", 0)
		requireMetric(t, metrics, fakemetrics.SetGaugeType, "stale", 0)
		require.Equal(t, float64(1), metricTotal(metrics, "expiry"))
		require.Zero(t, metricTotal(metrics, "readmission"))
	})

	t.Run("zero_disables_policy", func(t *testing.T) {
		responses := func(count int32) (*entryv1.GetAuthorizedEntriesResponse, error) {
			if count > 1 {
				return nil, errors.New("intentional synchronization failure")
			}
			return makeGetAuthorizedEntriesResponse(t, "resp3"), nil
		}
		m, clk, remoteTD := newFreshnessManager(t, 0, nil, responses)
		stop := runManager(t, m)
		defer stop()

		require.Error(t, m.synchronize(context.Background()))
		clk.Add(2 * testFreshnessLimit)
		require.Contains(t, m.GetBundles(), remoteTD)
	})

	t.Run("reports_aggregate_metrics", func(t *testing.T) {
		const limit = testFreshnessLimit
		backupTD := spiffeid.RequireTrustDomainFromString("backup.test")
		responses := func(int32) (*entryv1.GetAuthorizedEntriesResponse, error) {
			response := makeGetAuthorizedEntriesResponse(t, "resp3")
			response.Entries[1].FederatesWith = append(response.Entries[1].FederatesWith, backupTD.IDString())
			return response, nil
		}
		metrics := fakemetrics.New()
		m, clk, remoteTD := newFreshnessManager(t, limit, metrics, responses)
		stop := runManager(t, m)
		defer stop()

		require.Contains(t, m.GetBundles(), remoteTD)
		require.Contains(t, m.GetBundles(), backupTD)
		requireMetric(t, metrics, fakemetrics.SetGaugeType, "fresh", 2)
		requireMetric(t, metrics, fakemetrics.SetGaugeType, "stale", 0)
		requireMetric(t, metrics, fakemetrics.IncrCounterType, "expiry", 0)
		requireMetric(t, metrics, fakemetrics.IncrCounterType, "readmission", 0)

		clk.Add(limit / 2)
		require.NoError(t, m.synchronize(context.Background()))
		clk.Add(limit / 2)
		require.Contains(t, m.GetBundles(), remoteTD)
		require.Contains(t, m.GetBundles(), backupTD)

		clk.Add(limit / 2)
		require.Eventually(t, func() bool {
			return metricTotal(metrics, "expiry") == 2
		}, 2*time.Second, 10*time.Millisecond)
		requireMetric(t, metrics, fakemetrics.SetGaugeType, "fresh", 0)
		requireMetric(t, metrics, fakemetrics.SetGaugeType, "stale", 2)

		require.NoError(t, m.synchronize(context.Background()))
		requireMetric(t, metrics, fakemetrics.SetGaugeType, "fresh", 2)
		requireMetric(t, metrics, fakemetrics.SetGaugeType, "stale", 0)
		require.Equal(t, float64(2), metricTotal(metrics, "readmission"))

		requireAggregateFreshnessMetrics(t, metrics)
	})
}

type heldReattestation struct {
	agentsvid.Rotator
	entered chan struct{}
	release chan struct{}
}

func (r *heldReattestation) Run(context.Context) error {
	return fmt.Errorf("re-attestation requested: %w", errorutil.PermissionDenied(types.PermissionDeniedDetails_AGENT_MUST_REATTEST, "re-attestation requested"))
}

func (r *heldReattestation) Reattest(ctx context.Context) error {
	select {
	case r.entered <- struct{}{}:
	default:
	}
	select {
	case <-r.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func requireAggregateFreshnessMetrics(t *testing.T, metrics *fakemetrics.FakeMetrics) {
	t.Helper()
	series := make(map[string]map[string]struct{})
	for _, metric := range metrics.AllMetrics() {
		for _, suffix := range []string{"fresh", "stale", "expiry", "readmission"} {
			if isFreshnessMetric(metric.Key, suffix) {
				labels := make([]string, 0, len(metric.Labels))
				for _, label := range metric.Labels {
					labels = append(labels, fmt.Sprintf("%q=%q", label.Name, label.Value))
				}
				sort.Strings(labels)
				identity := strings.Join(metric.Key, "\x00") + "\x00" + strings.Join(labels, "\x00")
				if series[suffix] == nil {
					series[suffix] = make(map[string]struct{})
				}
				series[suffix][identity] = struct{}{}
			}
		}
	}
	for _, suffix := range []string{"fresh", "stale", "expiry", "readmission"} {
		require.Len(t, series[suffix], 1, "federated_bundle_%s must have one aggregate series", suffix)
	}
}

func newFreshnessManager(t *testing.T, limit time.Duration, metrics telemetry.Metrics, responses freshnessResponseFn) (*manager, *clock.Mock, spiffeid.TrustDomain) {
	return newFreshnessManagerWithEntries(t, limit, metrics, responses, "resp3")
}

func newFreshnessManagerWithEntries(t *testing.T, limit time.Duration, metrics telemetry.Metrics, responses freshnessResponseFn, entryKeys ...string) (*manager, *clock.Mock, spiffeid.TrustDomain) {
	t.Helper()
	dir := spiretest.TempDir(t)
	km := fakeagentkeymanager.New(t, dir)
	clk := clock.NewMock(t)
	if metrics == nil {
		metrics = &telemetry.Blackhole{}
	}
	if responses == nil {
		responses = func(int32) (*entryv1.GetAuthorizedEntriesResponse, error) {
			return makeGetAuthorizedEntriesResponse(t, entryKeys...), nil
		}
	}

	api := newMockAPI(t, &mockAPIConfig{
		km: km,
		getAuthorizedEntries: func(_ *mockAPI, count int32, _ *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
			return responses(count)
		},
		batchNewX509SVIDEntries: func(*mockAPI, int32) []*common.RegistrationEntry {
			return makeBatchNewX509SVIDEntries(entryKeys...)
		},
		svidTTL: int(time.Hour / time.Second),
		clk:     clk,
	})

	baseSVID, baseSVIDKey := api.newSVID(joinTokenID, time.Hour)
	catalog := fakeagentcatalog.New()
	catalog.SetKeyManager(km)
	config := &Config{
		ServerAddr:       api.addr,
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      trustDomain,
		Storage:          openStorage(t, dir),
		Bundle:           api.bundle,
		Metrics:          metrics,
		RotationInterval: time.Hour,
		SyncInterval:     time.Hour,
		Clk:              clk,
		Catalog:          catalog,
		WorkloadKeyType:  workloadkey.ECP256,
		SVIDStoreCache:   storecache.New(&storecache.Config{TrustDomain: trustDomain, Log: testLogger}),
		RotationStrategy: rotationutil.NewRotationStrategy(0),
	}

	configured := reflect.ValueOf(config).Elem().FieldByName("FederatedBundleMaxStaleness")
	require.True(t, configured.IsValid(), "manager.Config must expose FederatedBundleMaxStaleness")
	require.True(t, configured.CanSet())
	require.Equal(t, reflect.TypeFor[time.Duration](), configured.Type())
	configured.SetInt(int64(limit))

	m := newManager(config)
	require.NoError(t, m.Initialize(context.Background()))
	remoteTD := spiffeid.RequireTrustDomainFromString("otherdomain.test")
	require.Contains(t, m.GetBundles(), remoteTD)
	return m, clk, remoteTD
}

func requireMetric(t *testing.T, metrics *fakemetrics.FakeMetrics, metricType fakemetrics.MetricType, suffix string, expected float64) {
	t.Helper()
	all := metrics.AllMetrics()
	for _, a := range slices.Backward(all) {
		if a.Type == metricType && isFreshnessMetric(a.Key, suffix) {
			require.Equal(t, expected, a.Val)
			return
		}
	}
	t.Fatalf("federated_bundle_%s metric was not emitted", suffix)
}

func metricTotal(metrics *fakemetrics.FakeMetrics, suffix string) float64 {
	var total float64
	for _, metric := range metrics.AllMetrics() {
		if metric.Type == fakemetrics.IncrCounterType && isFreshnessMetric(metric.Key, suffix) {
			total += metric.Val
		}
	}
	return total
}

func isFreshnessMetric(key []string, suffix string) bool {
	return strings.HasSuffix(strings.Join(key, "_"), telemetry.FederatedBundle+"_"+suffix)
}
