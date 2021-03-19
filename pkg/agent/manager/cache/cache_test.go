package cache

import (
	"crypto/x509"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	trustDomain1  = spiffeid.RequireTrustDomainFromString("domain.test")
	trustDomain2  = spiffeid.RequireTrustDomainFromString("otherdomain.test")
	bundleV1      = bundleutil.BundleFromRootCA(trustDomain1, &x509.Certificate{Raw: []byte{1}})
	bundleV2      = bundleutil.BundleFromRootCA(trustDomain1, &x509.Certificate{Raw: []byte{2}})
	bundleV3      = bundleutil.BundleFromRootCA(trustDomain1, &x509.Certificate{Raw: []byte{3}})
	otherBundleV1 = bundleutil.BundleFromRootCA(trustDomain2, &x509.Certificate{Raw: []byte{4}})
	otherBundleV2 = bundleutil.BundleFromRootCA(trustDomain2, &x509.Certificate{Raw: []byte{5}})
	defaultTTL    = int32(600)
)

func TestFetchWorkloadUpdate(t *testing.T) {
	cache := newTestCache()
	// populate the cache with FOO and BAR without SVIDS
	foo := makeRegistrationEntry("FOO", "A")
	bar := makeRegistrationEntry("BAR", "B")
	bar.FederatesWith = makeFederatesWith(otherBundleV1)
	updateEntries := &UpdateEntries{
		Bundles:             makeBundles(bundleV1, otherBundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
	}
	cache.UpdateEntries(updateEntries, nil)

	workloadUpdate := cache.FetchWorkloadUpdate(makeSelectors("A", "B"))
	assert.Len(t, workloadUpdate.Identities, 0, "identities should not be returned that don't have SVIDs")

	updateSVIDs := &UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo, bar),
	}
	cache.UpdateSVIDs(updateSVIDs)

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
	updateEntries := &UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
	}
	cache.UpdateEntries(updateEntries, nil)

	identities := cache.MatchingIdentities(makeSelectors("A", "B"))
	assert.Len(t, identities, 0, "identities should not be returned that don't have SVIDs")

	updateSVIDs := &UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo, bar),
	}
	cache.UpdateSVIDs(updateSVIDs)

	identities = cache.MatchingIdentities(makeSelectors("A", "B"))
	assert.Equal(t, []Identity{
		{Entry: bar},
		{Entry: foo},
	}, identities)
}

func TestCountSVIDs(t *testing.T) {
	cache := newTestCache()

	// populate the cache with FOO and BAR without SVIDS
	foo := makeRegistrationEntry("FOO", "A")
	bar := makeRegistrationEntry("BAR", "B")
	updateEntries := &UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
	}
	cache.UpdateEntries(updateEntries, nil)

	// No SVIDs expected
	require.Equal(t, 0, cache.CountSVIDs())

	updateSVIDs := &UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	}
	cache.UpdateSVIDs(updateSVIDs)

	// Only one SVID expected
	require.Equal(t, 1, cache.CountSVIDs())
}

func TestBundleChanges(t *testing.T) {
	cache := newTestCache()

	bundleStream := cache.SubscribeToBundleChanges()
	assert.Equal(t, makeBundles(bundleV1), bundleStream.Value())

	cache.UpdateEntries(&UpdateEntries{
		Bundles: makeBundles(bundleV1, otherBundleV1),
	}, nil)
	if assert.True(t, bundleStream.HasNext(), "has new bundle value after adding bundle") {
		bundleStream.Next()
		assert.Equal(t, makeBundles(bundleV1, otherBundleV1), bundleStream.Value())
	}

	cache.UpdateEntries(&UpdateEntries{
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
	cache.UpdateEntries(&UpdateEntries{
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
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})

	// subscribe to A and B and assert initial updates are received.
	subA := cache.SubscribeToWorkloadUpdates(makeSelectors("A"))
	defer subA.Finish()
	assertAnyWorkloadUpdate(t, subA)

	subB := cache.SubscribeToWorkloadUpdates(makeSelectors("B"))
	defer subB.Finish()
	assertAnyWorkloadUpdate(t, subB)

	// add the federated bundle with no registration entries federating with
	// it and make sure nobody is notified.
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1, otherBundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	assertNoWorkloadUpdate(t, subA)
	assertNoWorkloadUpdate(t, subB)

	// update FOO to federate with otherdomain.test and make sure subA is
	// notified but not subB.
	foo = makeRegistrationEntry("FOO", "A")
	foo.FederatesWith = makeFederatesWith(otherBundleV1)
	cache.UpdateEntries(&UpdateEntries{
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
	cache.UpdateEntries(&UpdateEntries{
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
	cache.UpdateEntries(&UpdateEntries{
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
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
	}, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo, bar),
	})

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
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})

	sub := cache.SubscribeToWorkloadUpdates(makeSelectors("A"))
	defer sub.Finish()
	assertAnyWorkloadUpdate(t, sub)

	// Second update is the same (other than X509SVIDs, which, when set,
	// always constitute a "change" for the impacted registration entries.
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)

	assertNoWorkloadUpdate(t, sub)
}

func TestSubscriberNotifiedOnSVIDChanges(t *testing.T) {
	cache := newTestCache()

	foo := makeRegistrationEntry("FOO", "A")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})

	sub := cache.SubscribeToWorkloadUpdates(makeSelectors("A"))
	defer sub.Finish()
	assertAnyWorkloadUpdate(t, sub)

	// Update SVID
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})

	assertWorkloadUpdateEqual(t, sub, &WorkloadUpdate{
		Bundle:     bundleV1,
		Identities: []Identity{{Entry: foo}},
	})
}

func TestSubcriberNotificationsOnSelectorChanges(t *testing.T) {
	cache := newTestCache()

	// initialize the cache with a FOO entry with selector A and an SVID
	foo := makeRegistrationEntry("FOO", "A")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})

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
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})
	assertWorkloadUpdateEqual(t, sub, &WorkloadUpdate{
		Bundle: bundleV1,
	})

	// update FOO to drop B and make sure the subscriber regains FOO
	foo = makeRegistrationEntry("FOO", "A")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})

	assertWorkloadUpdateEqual(t, sub, &WorkloadUpdate{
		Bundle:     bundleV1,
		Identities: []Identity{{Entry: foo}},
	})
}

func newTestCache() *Cache {
	log, _ := test.NewNullLogger()
	return New(log, spiffeid.RequireTrustDomainFromString("domain.test"), bundleV1, telemetry.Blackhole{})
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
	updateEntries := &UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}
	cache.UpdateEntries(updateEntries, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})
	// make sure subA gets notified with FOO but not subB
	assertWorkloadUpdateEqual(t, subA, &WorkloadUpdate{
		Bundle:     bundleV1,
		Identities: []Identity{{Entry: foo}},
	})
	assertNoWorkloadUpdate(t, subB)

	updateEntries.RegistrationEntries = nil
	cache.UpdateEntries(updateEntries, nil)
	assertWorkloadUpdateEqual(t, subA, &WorkloadUpdate{
		Bundle: bundleV1,
	})
	assertNoWorkloadUpdate(t, subB)

	// Make sure trying to update SVIDs of removed entry does not notify
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})
	assertNoWorkloadUpdate(t, subB)
}

func TestSubcriberOnlyGetsEntriesWithSVID(t *testing.T) {
	cache := newTestCache()

	foo := makeRegistrationEntry("FOO", "A")
	updateEntries := &UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}
	cache.UpdateEntries(updateEntries, nil)

	sub := cache.SubscribeToWorkloadUpdates(makeSelectors("A"))
	defer sub.Finish()

	// workload update does not include the identity because it has no SVID.
	assertWorkloadUpdateEqual(t, sub, &WorkloadUpdate{
		Bundle: bundleV1,
	})

	// update to include the SVID and now we should get the update
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})
	assertWorkloadUpdateEqual(t, sub, &WorkloadUpdate{
		Bundle:     bundleV1,
		Identities: []Identity{{Entry: foo}},
	})
}

func TestSubscribersDoNotBlockNotifications(t *testing.T) {
	cache := newTestCache()

	sub := cache.SubscribeToWorkloadUpdates(makeSelectors("A"))
	defer sub.Finish()

	cache.UpdateEntries(&UpdateEntries{
		Bundles: makeBundles(bundleV2),
	}, nil)

	cache.UpdateEntries(&UpdateEntries{
		Bundles: makeBundles(bundleV3),
	}, nil)

	assertWorkloadUpdateEqual(t, sub, &WorkloadUpdate{
		Bundle: bundleV3,
	})
}

func TestCheckSVIDCallback(t *testing.T) {
	cache := newTestCache()

	// no calls because there are no registration entries
	cache.UpdateEntries(&UpdateEntries{
		Bundles: makeBundles(bundleV2),
	}, func(existingEntry, newEntry *common.RegistrationEntry, svid *X509SVID) bool {
		assert.Fail(t, "should not be called if there are no registration entries")

		return false
	})

	foo := makeRegistrationEntryWithTTL("FOO", 60)

	// called once for FOO with no SVID
	callCount := 0
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV2),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, func(existingEntry, newEntry *common.RegistrationEntry, svid *X509SVID) bool {
		callCount++
		assert.Equal(t, "FOO", newEntry.EntryId)

		// there is no already existing entry, only the new entry
		assert.Nil(t, existingEntry)
		assert.Equal(t, foo, newEntry)
		assert.Nil(t, svid)

		return false
	})
	assert.Equal(t, 1, callCount)
	assert.Empty(t, cache.staleEntries)

	// called once for FOO with new SVID
	callCount = 0
	svids := makeX509SVIDs(foo)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: svids,
	})

	// called once for FOO with existing SVID
	callCount = 0
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV2),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, func(existingEntry, newEntry *common.RegistrationEntry, svid *X509SVID) bool {
		callCount++
		assert.Equal(t, "FOO", newEntry.EntryId)
		if assert.NotNil(t, svid) {
			assert.Exactly(t, svids["FOO"], svid)
		}

		return true
	})
	assert.Equal(t, 1, callCount)
	assert.Equal(t, map[string]bool{foo.EntryId: true}, cache.staleEntries)
}

func TestGetStaleEntries(t *testing.T) {
	cache := newTestCache()

	foo := makeRegistrationEntryWithTTL("FOO", 60)

	// Create entry but don't mark it stale
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV2),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, func(existingEntry, newEntry *common.RegistrationEntry, svid *X509SVID) bool {
		return false
	})
	assert.Empty(t, cache.GetStaleEntries())

	// Update entry and mark it as stale
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV2),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, func(existingEntry, newEntry *common.RegistrationEntry, svid *X509SVID) bool {
		return true
	})
	// Assert that the entry is returned as stale. The `ExpiresAt` field should be unset since there is no SVID.
	expectedEntries := []*StaleEntry{{Entry: cache.records[foo.EntryId].entry}}
	assert.Equal(t, expectedEntries, cache.GetStaleEntries())

	// Update the SVID for the stale entry
	svids := make(map[string]*X509SVID)
	expiredAt := time.Now()
	svids[foo.EntryId] = &X509SVID{
		Chain: []*x509.Certificate{{NotAfter: expiredAt}},
	}
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: svids,
	})
	// Assert that updating the SVID removes stale marker from entry
	assert.Empty(t, cache.GetStaleEntries())

	// Update entry again and mark it as stale
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV2),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, func(existingEntry, newEntry *common.RegistrationEntry, svid *X509SVID) bool {
		return true
	})

	// Assert that the entry again returns as stale. This time the `ExpiresAt` field should be populated with the expiration of the SVID.
	expectedEntries = []*StaleEntry{{
		Entry:     cache.records[foo.EntryId].entry,
		ExpiresAt: expiredAt,
	}}
	assert.Equal(t, expectedEntries, cache.GetStaleEntries())

	// Remove registration entry and assert that it is no longer returned as stale
	cache.UpdateEntries(&UpdateEntries{
		Bundles: makeBundles(bundleV2),
	}, func(existingEntry, newEntry *common.RegistrationEntry, svid *X509SVID) bool {
		return true
	})
	assert.Empty(t, cache.GetStaleEntries())
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
	updateEntries := &UpdateEntries{
		Bundles:             bundlesV1,
		RegistrationEntries: make(map[string]*common.RegistrationEntry, numEntries),
	}
	for i := 0; i < numEntries; i++ {
		entryID := fmt.Sprintf("00000000-0000-0000-0000-%012d", i)
		updateEntries.RegistrationEntries[entryID] = &common.RegistrationEntry{
			EntryId:   entryID,
			ParentId:  "spiffe://domain.test/node",
			SpiffeId:  fmt.Sprintf("spiffe://domain.test/workload-%d", i),
			Selectors: distinctSelectors(i, selectorsPerEntry),
		}
	}

	cache.UpdateEntries(updateEntries, nil)
	for i := 0; i < numWorkloads; i++ {
		selectors := distinctSelectors(i, selectorsPerWorkload)
		cache.SubscribeToWorkloadUpdates(selectors)
	}

	runtime.GC()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if i%2 == 0 {
			updateEntries.Bundles = bundlesV2
		} else {
			updateEntries.Bundles = bundlesV1
		}
		cache.UpdateEntries(updateEntries, nil)
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

func makeBundles(bundles ...*Bundle) map[spiffeid.TrustDomain]*Bundle {
	out := make(map[spiffeid.TrustDomain]*Bundle)
	for _, bundle := range bundles {
		td := spiffeid.RequireTrustDomainFromString(bundle.TrustDomainID())
		out[td] = bundle
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
		DnsNames:  []string{fmt.Sprintf("name-%s", id)},
		Ttl:       defaultTTL,
	}
}

func makeRegistrationEntryWithTTL(id string, ttl int32, selectors ...string) *common.RegistrationEntry {
	return &common.RegistrationEntry{
		EntryId:   id,
		SpiffeId:  "spiffe://domain.test/" + id,
		Selectors: makeSelectors(selectors...),
		DnsNames:  []string{fmt.Sprintf("name-%s", id)},
		Ttl:       ttl,
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
