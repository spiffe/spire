package cache

import (
	"crypto/x509"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	mock_telemetry "github.com/spiffe/spire/test/mock/common/telemetry"
	"github.com/stretchr/testify/assert"
)

var (
	bundleV1      = bundleutil.BundleFromRootCA("spiffe://domain.test", &x509.Certificate{Raw: []byte{1}})
	bundleV2      = bundleutil.BundleFromRootCA("spiffe://domain.test", &x509.Certificate{Raw: []byte{2}})
	bundleV3      = bundleutil.BundleFromRootCA("spiffe://domain.test", &x509.Certificate{Raw: []byte{3}})
	otherBundleV1 = bundleutil.BundleFromRootCA("spiffe://otherdomain.test", &x509.Certificate{Raw: []byte{4}})
	otherBundleV2 = bundleutil.BundleFromRootCA("spiffe://otherdomain.test", &x509.Certificate{Raw: []byte{5}})
)

func TestFetchWorkloadUpdate(t *testing.T) {
	cache := newTestCache()
	// populate the cache with FOO and BAR without SVIDS
	foo := makeRegistrationEntry("FOO", "A")
	bar := makeRegistrationEntry("BAR", "B")
	bar.FederatesWith = makeFederatesWith(otherBundleV1)
	update := &CacheUpdate{
		Bundles:             makeBundles(bundleV1, otherBundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
	}
	cache.Update(update, nil)

	workloadUpdate := cache.FetchWorkloadUpdate(makeSelectors("A", "B"))
	assert.Len(t, workloadUpdate.Identities, 0, "identities should not be returned that don't have SVIDs")

	update.X509SVIDs = makeX509SVIDs(foo, bar)
	cache.Update(update, nil)

	workloadUpdate = cache.FetchWorkloadUpdate(makeSelectors("A", "B"))
	assert.Equal(t, &WorkloadUpdate{
		Bundle:           bundleV1,
		FederatedBundles: makeBundles(otherBundleV1),
		Identities: []Identity{
			{Entry: bar},
			{Entry: foo},
		},
	}, workloadUpdate)
}

func TestMatchingIdentities(t *testing.T) {
	cache := newTestCache()

	// populate the cache with FOO and BAR without SVIDS
	foo := makeRegistrationEntry("FOO", "A")
	bar := makeRegistrationEntry("BAR", "B")
	update := &CacheUpdate{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
	}
	cache.Update(update, nil)

	identities := cache.MatchingIdentities(makeSelectors("A", "B"))
	assert.Len(t, identities, 0, "identities should not be returned that don't have SVIDs")

	update.X509SVIDs = makeX509SVIDs(foo, bar)
	cache.Update(update, nil)

	identities = cache.MatchingIdentities(makeSelectors("A", "B"))
	assert.Equal(t, []Identity{
		{Entry: bar},
		{Entry: foo},
	}, identities)
}

func TestRegistrationEntryMetrics(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	metrics := mock_telemetry.NewMockMetrics(mockCtl)

	log, _ := test.NewNullLogger()
	cache := New(log, "spiffe://domain.test", bundleV1, metrics)

	// populate the cache with FOO and BAR without SVIDS
	foo := makeRegistrationEntry("FOO", "A")
	bar := makeRegistrationEntry("BAR", "B")
	update := &CacheUpdate{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
	}

	// Add two new entries
	metrics.EXPECT().IncrCounterWithLabels([]string{telemetry.CacheManager, telemetry.RegistrationEntry, telemetry.Create}, gomock.Any(),
		[]telemetry.Label{{Name: telemetry.SPIFFEID, Value: foo.SpiffeId}})
	metrics.EXPECT().IncrCounterWithLabels([]string{telemetry.CacheManager, telemetry.RegistrationEntry, telemetry.Create}, gomock.Any(),
		[]telemetry.Label{{Name: telemetry.SPIFFEID, Value: bar.SpiffeId}})

	cache.Update(update, nil)

	// Update foo
	foo.Selectors = makeSelectors("C")
	// delete bar
	delete(update.RegistrationEntries, bar.EntryId)

	// Update registration entry metric created
	metrics.EXPECT().IncrCounterWithLabels([]string{telemetry.CacheManager, telemetry.RegistrationEntry, telemetry.Update}, gomock.Any(),
		[]telemetry.Label{{Name: telemetry.SPIFFEID, Value: foo.SpiffeId}})
	// Delete registration entry metric created
	metrics.EXPECT().IncrCounterWithLabels([]string{telemetry.CacheManager, telemetry.RegistrationEntry, telemetry.Delete}, gomock.Any(),
		[]telemetry.Label{{Name: telemetry.SPIFFEID, Value: bar.SpiffeId}})

	cache.Update(update, nil)
}

func TestBundleChanges(t *testing.T) {
	cache := newTestCache()

	bundleStream := cache.SubscribeToBundleChanges()
	assert.Equal(t, makeBundles(bundleV1), bundleStream.Value())

	cache.Update(&CacheUpdate{
		Bundles: makeBundles(bundleV1, otherBundleV1),
	}, nil)
	if assert.True(t, bundleStream.HasNext(), "has new bundle value after adding bundle") {
		bundleStream.Next()
		assert.Equal(t, makeBundles(bundleV1, otherBundleV1), bundleStream.Value())
	}

	cache.Update(&CacheUpdate{
		Bundles: makeBundles(bundleV1),
	}, nil)

	if assert.True(t, bundleStream.HasNext(), "has new bundle value after removing bundle") {
		bundleStream.Next()
		assert.Equal(t, makeBundles(bundleV1), bundleStream.Value())
	}
}

func TestAllSubscribersNotifiedOnBundleChange(t *testing.T) {
	cache := newTestCache()

	// create some subscribers and assert they get the initial bundle
	subA := cache.SubscribeToWorkloadUpdates(makeSelectors("A"))
	defer subA.Finish()
	assertWorkloadUpdateEqual(t, subA, &WorkloadUpdate{Bundle: bundleV1})

	subB := cache.SubscribeToWorkloadUpdates(makeSelectors("B"))
	defer subB.Finish()
	assertWorkloadUpdateEqual(t, subB, &WorkloadUpdate{Bundle: bundleV1})

	// update the bundle and assert all subscribers gets the updated bundle
	cache.Update(&CacheUpdate{
		Bundles: makeBundles(bundleV2),
	}, nil)
	assertWorkloadUpdateEqual(t, subA, &WorkloadUpdate{Bundle: bundleV2})
	assertWorkloadUpdateEqual(t, subB, &WorkloadUpdate{Bundle: bundleV2})
}

func TestSomeSubscribersNotifiedOnFederatedBundleChange(t *testing.T) {
	cache := newTestCache()

	// initialize the cache with an entry FOO that has a valid SVID and
	// selector "A"
	foo := makeRegistrationEntry("FOO", "A")
	cache.Update(&CacheUpdate{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
		X509SVIDs:           makeX509SVIDs(foo),
	}, nil)

	// subscribe to A and B and assert initial updates are received.
	subA := cache.SubscribeToWorkloadUpdates(makeSelectors("A"))
	defer subA.Finish()
	assertAnyWorkloadUpdate(t, subA)

	subB := cache.SubscribeToWorkloadUpdates(makeSelectors("B"))
	defer subB.Finish()
	assertAnyWorkloadUpdate(t, subB)

	// add the federated bundle with no registration entries federating with
	// it and make sure nobody is notified.
	cache.Update(&CacheUpdate{
		Bundles:             makeBundles(bundleV1, otherBundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	assertNoWorkloadUpdate(t, subA)
	assertNoWorkloadUpdate(t, subB)

	// update FOO to federate with otherdomain.test and make sure subA is
	// notified but not subB.
	foo = makeRegistrationEntry("FOO", "A")
	foo.FederatesWith = makeFederatesWith(otherBundleV1)
	cache.Update(&CacheUpdate{
		Bundles:             makeBundles(bundleV1, otherBundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	assertWorkloadUpdateEqual(t, subA, &WorkloadUpdate{
		Bundle:           bundleV1,
		FederatedBundles: makeBundles(otherBundleV1),
		Identities:       []Identity{{Entry: foo}},
	})
	assertNoWorkloadUpdate(t, subB)

	// now change the federated bundle and make sure subA gets notified, but
	// again, not subB.
	cache.Update(&CacheUpdate{
		Bundles:             makeBundles(bundleV1, otherBundleV2),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	assertWorkloadUpdateEqual(t, subA, &WorkloadUpdate{
		Bundle:           bundleV1,
		FederatedBundles: makeBundles(otherBundleV2),
		Identities:       []Identity{{Entry: foo}},
	})
	assertNoWorkloadUpdate(t, subB)

	// now drop the federation and make sure subA is again notified and no
	// longer has the federated bundle.
	foo = makeRegistrationEntry("FOO", "A")
	cache.Update(&CacheUpdate{
		Bundles:             makeBundles(bundleV1, otherBundleV2),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	assertWorkloadUpdateEqual(t, subA, &WorkloadUpdate{
		Bundle:     bundleV1,
		Identities: []Identity{{Entry: foo}},
	})
	assertNoWorkloadUpdate(t, subB)
}

func TestSubscribersGetEntriesWithSelectorSubsets(t *testing.T) {
	cache := newTestCache()

	// create subscribers for each combination of selectors
	subA := cache.SubscribeToWorkloadUpdates(makeSelectors("A"))
	defer subA.Finish()
	subB := cache.SubscribeToWorkloadUpdates(makeSelectors("B"))
	defer subB.Finish()
	subAB := cache.SubscribeToWorkloadUpdates(makeSelectors("A", "B"))
	defer subAB.Finish()

	// assert all subscribers get the initial update
	initialUpdate := &WorkloadUpdate{Bundle: bundleV1}
	assertWorkloadUpdateEqual(t, subA, initialUpdate)
	assertWorkloadUpdateEqual(t, subB, initialUpdate)
	assertWorkloadUpdateEqual(t, subAB, initialUpdate)

	// create entry FOO that will target any subscriber with containing (A)
	foo := makeRegistrationEntry("FOO", "A")

	// create entry BAR that will target any subscriber with containing (A,C)
	bar := makeRegistrationEntry("BAR", "A", "C")

	// update the cache with foo and bar
	cache.Update(&CacheUpdate{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
		X509SVIDs:           makeX509SVIDs(foo, bar),
	}, nil)

	// subA selector set contains (A), but not (A, C), so it should only get FOO
	assertWorkloadUpdateEqual(t, subA, &WorkloadUpdate{
		Bundle:     bundleV1,
		Identities: []Identity{{Entry: foo}},
	})

	// subB selector set does not contain either (A) or (A,C) so it isn't even
	// notified.
	assertNoWorkloadUpdate(t, subB)

	// subAB selector set contains (A) but not (A, C), so it should get FOO
	assertWorkloadUpdateEqual(t, subAB, &WorkloadUpdate{
		Bundle:     bundleV1,
		Identities: []Identity{{Entry: foo}},
	})
}

func TestSubscriberIsNotNotifiedIfNothingChanges(t *testing.T) {
	cache := newTestCache()

	foo := makeRegistrationEntry("FOO", "A")
	cache.Update(&CacheUpdate{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
		X509SVIDs:           makeX509SVIDs(foo),
	}, nil)

	sub := cache.SubscribeToWorkloadUpdates(makeSelectors("A"))
	defer sub.Finish()
	assertAnyWorkloadUpdate(t, sub)

	// Second update is the same (other than X509SVIDs, which, when set,
	// always constitute a "change" for the impacted registration entries.
	cache.Update(&CacheUpdate{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)

	assertNoWorkloadUpdate(t, sub)
}

func TestSubcriberNotificationsOnSelectorChanges(t *testing.T) {
	cache := newTestCache()

	// initialize the cache with a FOO entry with selector A and an SVID
	foo := makeRegistrationEntry("FOO", "A")
	cache.Update(&CacheUpdate{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
		X509SVIDs:           makeX509SVIDs(foo),
	}, nil)

	// create subscribers for A and make sure the initial update has FOO
	sub := cache.SubscribeToWorkloadUpdates(makeSelectors("A"))
	defer sub.Finish()
	assertWorkloadUpdateEqual(t, sub, &WorkloadUpdate{
		Bundle:     bundleV1,
		Identities: []Identity{{Entry: foo}},
	})

	// update FOO to have selectors (A,B) and make sure the subscriber loses
	// FOO, since (A,B) is not a subset of the subscriber set (A).
	foo = makeRegistrationEntry("FOO", "A", "B")
	cache.Update(&CacheUpdate{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
		X509SVIDs:           makeX509SVIDs(foo),
	}, nil)
	assertWorkloadUpdateEqual(t, sub, &WorkloadUpdate{
		Bundle: bundleV1,
	})

	// update FOO to drop B and make sure the subscriber regains FOO
	foo = makeRegistrationEntry("FOO", "A")
	cache.Update(&CacheUpdate{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
		X509SVIDs:           makeX509SVIDs(foo),
	}, nil)
	assertWorkloadUpdateEqual(t, sub, &WorkloadUpdate{
		Bundle:     bundleV1,
		Identities: []Identity{{Entry: foo}},
	})
}

func newTestCache() *Cache {
	log, _ := test.NewNullLogger()
	return New(log, "spiffe://domain.test", bundleV1, telemetry.Blackhole{})
}

func TestSubcriberNotifiedWhenEntryDropped(t *testing.T) {
	cache := newTestCache()

	subA := cache.SubscribeToWorkloadUpdates(makeSelectors("A"))
	defer subA.Finish()
	assertAnyWorkloadUpdate(t, subA)

	// subB's job here is to just make sure we don't notify unrelated
	// subscribers when dropping registration entries
	subB := cache.SubscribeToWorkloadUpdates(makeSelectors("B"))
	defer subB.Finish()
	assertAnyWorkloadUpdate(t, subB)

	foo := makeRegistrationEntry("FOO", "A")
	update := &CacheUpdate{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
		X509SVIDs:           makeX509SVIDs(foo),
	}
	cache.Update(update, nil)

	// make sure subA gets notified with FOO but not subB
	assertWorkloadUpdateEqual(t, subA, &WorkloadUpdate{
		Bundle:     bundleV1,
		Identities: []Identity{{Entry: foo}},
	})
	assertNoWorkloadUpdate(t, subB)

	// drop FOO and make sure subA gets notified but not subB
	update.RegistrationEntries = nil
	cache.Update(update, nil)
	assertWorkloadUpdateEqual(t, subA, &WorkloadUpdate{
		Bundle: bundleV1,
	})
	assertNoWorkloadUpdate(t, subB)
}

func TestSubcriberOnlyGetsEntriesWithSVID(t *testing.T) {
	cache := newTestCache()

	foo := makeRegistrationEntry("FOO", "A")
	update := &CacheUpdate{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}
	cache.Update(update, nil)

	sub := cache.SubscribeToWorkloadUpdates(makeSelectors("A"))
	defer sub.Finish()

	// workload update does not include the identity because it has no SVID.
	assertWorkloadUpdateEqual(t, sub, &WorkloadUpdate{
		Bundle: bundleV1,
	})

	// update to include the SVID and now we should get the update
	update.X509SVIDs = makeX509SVIDs(foo)
	cache.Update(update, nil)
	assertWorkloadUpdateEqual(t, sub, &WorkloadUpdate{
		Bundle:     bundleV1,
		Identities: []Identity{{Entry: foo}},
	})
}

func TestSubscribersDoNotBlockNotifications(t *testing.T) {
	cache := newTestCache()

	sub := cache.SubscribeToWorkloadUpdates(makeSelectors("A"))
	defer sub.Finish()

	cache.Update(&CacheUpdate{
		Bundles: makeBundles(bundleV2),
	}, nil)

	cache.Update(&CacheUpdate{
		Bundles: makeBundles(bundleV3),
	}, nil)

	assertWorkloadUpdateEqual(t, sub, &WorkloadUpdate{
		Bundle: bundleV3,
	})
}

func TestCheckSVIDCallback(t *testing.T) {
	cache := newTestCache()

	// no calls because there are no registration entries
	cache.Update(&CacheUpdate{
		Bundles: makeBundles(bundleV2),
	}, func(entry *common.RegistrationEntry, svid *X509SVID) {
		assert.Fail(t, "should not be called if there are no registration entries")
	})

	foo := makeRegistrationEntry("FOO")

	// called once for FOO with no SVID
	callCount := 0
	cache.Update(&CacheUpdate{
		Bundles:             makeBundles(bundleV2),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, func(entry *common.RegistrationEntry, svid *X509SVID) {
		callCount++
		assert.Equal(t, "FOO", entry.EntryId)
		assert.Nil(t, svid)
	})
	assert.Equal(t, 1, callCount)

	// called once for FOO with new SVID
	callCount = 0
	svids := makeX509SVIDs(foo)
	cache.Update(&CacheUpdate{
		Bundles:             makeBundles(bundleV2),
		RegistrationEntries: makeRegistrationEntries(foo),
		X509SVIDs:           svids,
	}, func(entry *common.RegistrationEntry, svid *X509SVID) {
		callCount++
		assert.Equal(t, "FOO", entry.EntryId)
		if assert.NotNil(t, svid) {
			assert.Exactly(t, svids["FOO"], svid)
		}
	})
	assert.Equal(t, 1, callCount)

	// called once for FOO with existing SVID
	callCount = 0
	cache.Update(&CacheUpdate{
		Bundles:             makeBundles(bundleV2),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, func(entry *common.RegistrationEntry, svid *X509SVID) {
		callCount++
		assert.Equal(t, "FOO", entry.EntryId)
		if assert.NotNil(t, svid) {
			assert.Exactly(t, svids["FOO"], svid)
		}
	})
	assert.Equal(t, 1, callCount)
}

func BenchmarkCacheGlobalNotification(b *testing.B) {
	cache := newTestCache()

	const numEntries = 1000
	const numWorkloads = 1000
	const selectorsPerEntry = 3
	const selectorsPerWorkload = 10

	// build a set of 1000 registration entries with distinct selectors
	bundlesV1 := makeBundles(bundleV1)
	bundlesV2 := makeBundles(bundleV2)
	update := &CacheUpdate{
		Bundles:             bundlesV1,
		RegistrationEntries: make(map[string]*common.RegistrationEntry, numEntries),
		X509SVIDs:           make(map[string]*X509SVID, numEntries),
	}
	for i := 0; i < numEntries; i++ {
		entryID := fmt.Sprintf("00000000-0000-0000-0000-%012d", i)
		update.RegistrationEntries[entryID] = &common.RegistrationEntry{
			EntryId:   entryID,
			ParentId:  "spiffe://domain.test/node",
			SpiffeId:  fmt.Sprintf("spiffe://domain.test/workload-%d", i),
			Selectors: distinctSelectors(i, selectorsPerEntry),
		}
	}

	cache.Update(update, nil)
	update.X509SVIDs = nil

	for i := 0; i < numWorkloads; i++ {
		selectors := distinctSelectors(i, selectorsPerWorkload)
		cache.SubscribeToWorkloadUpdates(selectors)
	}

	runtime.GC()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if i%2 == 0 {
			update.Bundles = bundlesV2
		} else {
			update.Bundles = bundlesV1
		}
		cache.Update(update, nil)
	}
}

func distinctSelectors(id, n int) []*common.Selector {
	out := make([]*common.Selector, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, &common.Selector{
			Type:  "test",
			Value: fmt.Sprintf("id:%d:n:%d", id, i),
		})
	}
	return out
}

func assertNoWorkloadUpdate(t *testing.T, sub Subscriber) {
	select {
	case update := <-sub.Updates():
		assert.FailNow(t, "unexpected workload update", update)
	default:
	}
}

func assertAnyWorkloadUpdate(t *testing.T, sub Subscriber) {
	select {
	case <-sub.Updates():
	case <-time.After(time.Minute):
		assert.FailNow(t, "timed out waiting for any workload update")
	}
}

func assertWorkloadUpdateEqual(t *testing.T, sub Subscriber, expected *WorkloadUpdate) {
	select {
	case actual := <-sub.Updates():
		assert.NotNil(t, actual.Bundle, "bundle is not set")
		assert.True(t, actual.Bundle.EqualTo(expected.Bundle), "bundles don't match")
		assert.Equal(t, expected.Identities, actual.Identities, "identities don't match")
	case <-time.After(time.Minute):
		assert.FailNow(t, "timed out waiting for workload update")
	}
}

func makeBundles(bundles ...*Bundle) map[string]*Bundle {
	out := make(map[string]*Bundle)
	for _, bundle := range bundles {
		out[bundle.TrustDomainID()] = bundle
	}
	return out
}

func makeX509SVIDs(entries ...*common.RegistrationEntry) map[string]*X509SVID {
	out := make(map[string]*X509SVID)
	for _, entry := range entries {
		out[entry.EntryId] = &X509SVID{}
	}
	return out
}

func makeRegistrationEntry(id string, selectors ...string) *common.RegistrationEntry {
	return &common.RegistrationEntry{
		EntryId:   id,
		SpiffeId:  "spiffe://domain.test/" + id,
		Selectors: makeSelectors(selectors...),
	}
}

func makeRegistrationEntries(entries ...*common.RegistrationEntry) map[string]*common.RegistrationEntry {
	out := make(map[string]*common.RegistrationEntry)
	for _, entry := range entries {
		out[entry.EntryId] = entry
	}
	return out
}

func makeSelectors(values ...string) []*common.Selector {
	var out []*common.Selector
	for _, value := range values {
		out = append(out, &common.Selector{Type: "test", Value: value})
	}
	return out
}

func makeFederatesWith(bundles ...*Bundle) []string {
	var out []string
	for _, bundle := range bundles {
		out = append(out, bundle.TrustDomainID())
	}
	return out
}
