package cache

import (
	"context"
	"crypto/x509"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLRUCacheFetchWorkloadUpdate(t *testing.T) {
	cache := newTestLRUCache(t)
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

func TestLRUCacheMatchingRegistrationIdentities(t *testing.T) {
	cache := newTestLRUCache(t)

	// populate the cache with FOO and BAR without SVIDS
	foo := makeRegistrationEntry("FOO", "A")
	bar := makeRegistrationEntry("BAR", "B")
	updateEntries := &UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
	}
	cache.UpdateEntries(updateEntries, nil)

	assert.Equal(t, []*common.RegistrationEntry{bar, foo},
		cache.MatchingRegistrationEntries(makeSelectors("A", "B")))

	// Update SVIDs and MatchingRegistrationEntries should return both entries
	updateSVIDs := &UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo, bar),
	}
	cache.UpdateSVIDs(updateSVIDs)
	assert.Equal(t, []*common.RegistrationEntry{bar, foo},
		cache.MatchingRegistrationEntries(makeSelectors("A", "B")))

	// Remove SVIDs and MatchingRegistrationEntries should still return both entries
	cache.UpdateSVIDs(&UpdateSVIDs{})
	assert.Equal(t, []*common.RegistrationEntry{bar, foo},
		cache.MatchingRegistrationEntries(makeSelectors("A", "B")))
}

func TestLRUCacheCountSVIDs(t *testing.T) {
	cache := newTestLRUCache(t)

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

func TestLRUCacheCountRecords(t *testing.T) {
	cache := newTestLRUCache(t)
	// populate the cache with FOO and BAR without SVIDS
	foo := makeRegistrationEntry("FOO", "A")
	bar := makeRegistrationEntry("BAR", "B")
	updateEntries := &UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
	}
	cache.UpdateEntries(updateEntries, nil)
	require.Equal(t, 2, cache.CountRecords())
}

func TestLRUCacheBundleChanges(t *testing.T) {
	cache := newTestLRUCache(t)

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

func TestLRUCacheAllSubscribersNotifiedOnBundleChange(t *testing.T) {
	cache := newTestLRUCache(t)

	// create some subscribers and assert they get the initial bundle
	subA := subscribeToWorkloadUpdates(t, cache, makeSelectors("A"))
	defer subA.Finish()
	assertWorkloadUpdateEqual(t, subA, &WorkloadUpdate{Bundle: bundleV1})

	subB := subscribeToWorkloadUpdates(t, cache, makeSelectors("B"))
	defer subB.Finish()
	assertWorkloadUpdateEqual(t, subB, &WorkloadUpdate{Bundle: bundleV1})

	// update the bundle and assert all subscribers gets the updated bundle
	cache.UpdateEntries(&UpdateEntries{
		Bundles: makeBundles(bundleV2),
	}, nil)
	assertWorkloadUpdateEqual(t, subA, &WorkloadUpdate{Bundle: bundleV2})
	assertWorkloadUpdateEqual(t, subB, &WorkloadUpdate{Bundle: bundleV2})
}

func TestLRUCacheSomeSubscribersNotifiedOnFederatedBundleChange(t *testing.T) {
	cache := newTestLRUCache(t)

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
	subA := subscribeToWorkloadUpdates(t, cache, makeSelectors("A"))
	defer subA.Finish()
	assertAnyWorkloadUpdate(t, subA)

	subB := subscribeToWorkloadUpdates(t, cache, makeSelectors("B"))
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

func TestLRUCacheSubscribersGetEntriesWithSelectorSubsets(t *testing.T) {
	cache := newTestLRUCache(t)

	// create subscribers for each combination of selectors
	subA := subscribeToWorkloadUpdates(t, cache, makeSelectors("A"))
	defer subA.Finish()
	subB := subscribeToWorkloadUpdates(t, cache, makeSelectors("B"))
	defer subB.Finish()
	subAB := subscribeToWorkloadUpdates(t, cache, makeSelectors("A", "B"))
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

func TestLRUCacheSubscriberIsNotNotifiedIfNothingChanges(t *testing.T) {
	cache := newTestLRUCache(t)

	foo := makeRegistrationEntry("FOO", "A")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})

	sub := subscribeToWorkloadUpdates(t, cache, makeSelectors("A"))
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

func TestLRUCacheSubscriberNotifiedOnSVIDChanges(t *testing.T) {
	cache := newTestLRUCache(t)

	foo := makeRegistrationEntry("FOO", "A")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})

	sub := subscribeToWorkloadUpdates(t, cache, makeSelectors("A"))
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

func TestLRUCacheSubscriberNotificationsOnSelectorChanges(t *testing.T) {
	cache := newTestLRUCache(t)

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
	sub := subscribeToWorkloadUpdates(t, cache, makeSelectors("A"))
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

func TestLRUCacheSubscriberNotifiedWhenEntryDropped(t *testing.T) {
	cache := newTestLRUCache(t)

	subA := subscribeToWorkloadUpdates(t, cache, makeSelectors("A"))
	defer subA.Finish()
	assertAnyWorkloadUpdate(t, subA)

	// subB's job here is to just make sure we don't notify unrelated
	// subscribers when dropping registration entries
	subB := subscribeToWorkloadUpdates(t, cache, makeSelectors("B"))
	defer subB.Finish()
	assertAnyWorkloadUpdate(t, subB)

	foo := makeRegistrationEntry("FOO", "A")
	bar := makeRegistrationEntry("BAR", "B")

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

	// Swap out FOO for BAR
	updateEntries.RegistrationEntries = makeRegistrationEntries(bar)
	cache.UpdateEntries(updateEntries, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(bar),
	})
	assertWorkloadUpdateEqual(t, subA, &WorkloadUpdate{
		Bundle: bundleV1,
	})
	assertWorkloadUpdateEqual(t, subB, &WorkloadUpdate{
		Bundle:     bundleV1,
		Identities: []Identity{{Entry: bar}},
	})

	// Drop both
	updateEntries.RegistrationEntries = nil
	cache.UpdateEntries(updateEntries, nil)
	assertNoWorkloadUpdate(t, subA)
	assertWorkloadUpdateEqual(t, subB, &WorkloadUpdate{
		Bundle: bundleV1,
	})

	// Make sure trying to update SVIDs of removed entry does not notify
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})
	assertNoWorkloadUpdate(t, subB)
}

func TestLRUCacheSubscriberOnlyGetsEntriesWithSVID(t *testing.T) {
	cache := newTestLRUCache(t)

	foo := makeRegistrationEntry("FOO", "A")
	updateEntries := &UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}
	cache.UpdateEntries(updateEntries, nil)

	sub := cache.NewSubscriber(makeSelectors("A"))
	defer sub.Finish()
	assertNoWorkloadUpdate(t, sub)

	// update to include the SVID and now we should get the update
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})
	assertWorkloadUpdateEqual(t, sub, &WorkloadUpdate{
		Bundle:     bundleV1,
		Identities: []Identity{{Entry: foo}},
	})
}

func TestLRUCacheSubscribersDoNotBlockNotifications(t *testing.T) {
	cache := newTestLRUCache(t)

	sub := subscribeToWorkloadUpdates(t, cache, makeSelectors("A"))
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

func TestLRUCacheCheckSVIDCallback(t *testing.T) {
	cache := newTestLRUCache(t)

	// no calls because there are no registration entries
	cache.UpdateEntries(&UpdateEntries{
		Bundles: makeBundles(bundleV2),
	}, func(existingEntry, newEntry *common.RegistrationEntry, svid *X509SVID) bool {
		assert.Fail(t, "should not be called if there are no registration entries")

		return false
	})

	foo := makeRegistrationEntryWithTTL("FOO", 70, 80)

	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV2),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, func(existingEntry, newEntry *common.RegistrationEntry, svid *X509SVID) bool {
		// should not get invoked
		assert.Fail(t, "should not be called as no SVIDs are cached yet")
		return false
	})

	// called once for FOO with new SVID
	svids := makeX509SVIDs(foo)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: svids,
	})

	// called once for FOO with existing SVID
	callCount := 0
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

func TestLRUCacheGetStaleEntries(t *testing.T) {
	cache := newTestLRUCache(t)

	bar := makeRegistrationEntryWithTTL("BAR", 130, 140, "B")

	// Create entry but don't mark it stale from checkSVID method;
	// it will be marked stale cause it does not have SVID cached
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV2),
		RegistrationEntries: makeRegistrationEntries(bar),
	}, func(existingEntry, newEntry *common.RegistrationEntry, svid *X509SVID) bool {
		return false
	})

	// Assert that the entry is returned as stale. The `ExpiresAt` field should be unset since there is no SVID.
	expectedEntries := []*StaleEntry{{Entry: cache.records[bar.EntryId].entry}}
	assert.Equal(t, expectedEntries, cache.GetStaleEntries())

	// Update the SVID for the stale entry
	svids := make(map[string]*X509SVID)
	expiredAt := time.Now()
	svids[bar.EntryId] = &X509SVID{
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
		RegistrationEntries: makeRegistrationEntries(bar),
	}, func(existingEntry, newEntry *common.RegistrationEntry, svid *X509SVID) bool {
		return true
	})

	// Assert that the entry again returns as stale. This time the `ExpiresAt` field should be populated with the expiration of the SVID.
	expectedEntries = []*StaleEntry{{
		Entry:         cache.records[bar.EntryId].entry,
		SVIDExpiresAt: expiredAt,
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

func TestLRUCacheSubscriberNotNotifiedOnDifferentSVIDChanges(t *testing.T) {
	cache := newTestLRUCache(t)

	foo := makeRegistrationEntry("FOO", "A")
	bar := makeRegistrationEntry("BAR", "B")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
	}, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo, bar),
	})

	sub := subscribeToWorkloadUpdates(t, cache, makeSelectors("A"))
	defer sub.Finish()
	assertAnyWorkloadUpdate(t, sub)

	// Update SVID
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(bar),
	})

	assertNoWorkloadUpdate(t, sub)
}

func TestLRUCacheSubscriberNotNotifiedOnOverlappingSVIDChanges(t *testing.T) {
	cache := newTestLRUCache(t)

	foo := makeRegistrationEntry("FOO", "A", "C")
	bar := makeRegistrationEntry("FOO", "A", "B")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo, bar),
	})

	sub := subscribeToWorkloadUpdates(t, cache, makeSelectors("A", "B"))
	defer sub.Finish()
	assertAnyWorkloadUpdate(t, sub)

	// Update SVID
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})

	assertNoWorkloadUpdate(t, sub)
}

func TestLRUCacheSVIDCacheExpiry(t *testing.T) {
	clk := clock.NewMock(t)
	cache := newTestLRUCacheWithConfig(10, clk)

	clk.Add(1 * time.Second)
	foo := makeRegistrationEntry("FOO", "A")
	// validate workload update for foo
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})
	subA := subscribeToWorkloadUpdates(t, cache, makeSelectors("A"))
	assertWorkloadUpdateEqual(t, subA, &WorkloadUpdate{
		Bundle:     bundleV1,
		Identities: []Identity{{Entry: foo}},
	})
	subA.Finish()

	// move clk by 1 sec so that SVID access time will be different
	clk.Add(1 * time.Second)
	bar := makeRegistrationEntry("BAR", "B")
	// validate workload update for bar
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
	}, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(bar),
	})

	// not closing subscriber immediately
	subB := subscribeToWorkloadUpdates(t, cache, makeSelectors("B"))
	defer subB.Finish()
	assertWorkloadUpdateEqual(t, subB, &WorkloadUpdate{
		Bundle: bundleV1,
		Identities: []Identity{
			{Entry: bar},
		},
	})

	// Move clk by 2 seconds
	clk.Add(2 * time.Second)
	// update total of 12 entries
	updateEntries := createUpdateEntries(10, makeBundles(bundleV1))
	updateEntries.RegistrationEntries[foo.EntryId] = foo
	updateEntries.RegistrationEntries[bar.EntryId] = bar

	cache.UpdateEntries(updateEntries, nil)

	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDsFromMap(updateEntries.RegistrationEntries),
	})

	for id, entry := range updateEntries.RegistrationEntries {
		// create and close subscribers for remaining entries so that svid cache is full
		if id != foo.EntryId && id != bar.EntryId {
			sub := cache.NewSubscriber(entry.Selectors)
			sub.Finish()
		}
	}
	assert.Equal(t, 12, cache.CountSVIDs())

	cache.UpdateEntries(updateEntries, nil)
	assert.Equal(t, 10, cache.CountSVIDs())

	// foo SVID should be removed from cache as it does not have active subscriber
	assert.False(t, cache.notifySubscriberIfSVIDAvailable(makeSelectors("A"), subA.(*lruCacheSubscriber)))
	// bar SVID should be cached as it has active subscriber
	assert.True(t, cache.notifySubscriberIfSVIDAvailable(makeSelectors("B"), subB.(*lruCacheSubscriber)))

	subA = cache.NewSubscriber(makeSelectors("A"))
	defer subA.Finish()

	cache.UpdateEntries(updateEntries, nil)

	// Make sure foo is marked as stale entry which does not have svid cached
	require.Len(t, cache.GetStaleEntries(), 1)
	assert.Equal(t, foo, cache.GetStaleEntries()[0].Entry)

	assert.Equal(t, 10, cache.CountSVIDs())
}

func TestLRUCacheMaxSVIDCacheSize(t *testing.T) {
	clk := clock.NewMock(t)
	cache := newTestLRUCacheWithConfig(10, clk)

	// create entries more than maxSvidCacheSize
	updateEntries := createUpdateEntries(12, makeBundles(bundleV1))
	cache.UpdateEntries(updateEntries, nil)

	require.Len(t, cache.GetStaleEntries(), 10)

	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDsFromStaleEntries(cache.GetStaleEntries()),
	})
	require.Len(t, cache.GetStaleEntries(), 0)
	assert.Equal(t, 10, cache.CountSVIDs())

	// Validate that active subscriber will still get SVID even if SVID count is at maxSvidCacheSize
	foo := makeRegistrationEntry("FOO", "A")
	updateEntries.RegistrationEntries[foo.EntryId] = foo

	subA := cache.NewSubscriber(foo.Selectors)
	defer subA.Finish()

	cache.UpdateEntries(updateEntries, nil)
	require.Len(t, cache.GetStaleEntries(), 1)
	assert.Equal(t, 10, cache.CountSVIDs())

	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})
	assert.Equal(t, 11, cache.CountSVIDs())
	require.Len(t, cache.GetStaleEntries(), 0)
}

func TestSyncSVIDsWithSubscribers(t *testing.T) {
	clk := clock.NewMock(t)
	cache := newTestLRUCacheWithConfig(5, clk)

	updateEntries := createUpdateEntries(5, makeBundles(bundleV1))
	cache.UpdateEntries(updateEntries, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDsFromStaleEntries(cache.GetStaleEntries()),
	})
	assert.Equal(t, 5, cache.CountSVIDs())

	// Update foo but its SVID is not yet cached
	foo := makeRegistrationEntry("FOO", "A")
	updateEntries.RegistrationEntries[foo.EntryId] = foo

	cache.UpdateEntries(updateEntries, nil)

	// Create a subscriber for foo
	subA := cache.NewSubscriber(foo.Selectors)
	defer subA.Finish()
	require.Len(t, cache.GetStaleEntries(), 0)

	// After SyncSVIDsWithSubscribers foo should be marked as stale, requiring signing
	cache.SyncSVIDsWithSubscribers()
	require.Len(t, cache.GetStaleEntries(), 1)
	assert.Equal(t, []*StaleEntry{{Entry: cache.records[foo.EntryId].entry}}, cache.GetStaleEntries())

	assert.Equal(t, 5, cache.CountSVIDs())
}

func TestNotifySubscriberWhenSVIDIsAvailable(t *testing.T) {
	cache := newTestLRUCache(t)

	subscriber := cache.NewSubscriber(makeSelectors("A"))
	sub, ok := subscriber.(*lruCacheSubscriber)
	require.True(t, ok)

	foo := makeRegistrationEntry("FOO", "A")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)

	assert.False(t, cache.notifySubscriberIfSVIDAvailable(makeSelectors("A"), sub))
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})
	assert.True(t, cache.notifySubscriberIfSVIDAvailable(makeSelectors("A"), sub))
}

func TestSubscribeToWorkloadUpdatesLRUNoSelectors(t *testing.T) {
	clk := clock.NewMock(t)
	cache := newTestLRUCacheWithConfig(1, clk)

	// Creating test entries, but this will not affect current test...
	foo := makeRegistrationEntry("FOO", "A")
	bar := makeRegistrationEntry("BAR", "B")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
	}, nil)

	subWaitCh := make(chan struct{}, 1)
	subErrCh := make(chan error, 1)
	go func() {
		sub1, err := cache.subscribeToWorkloadUpdates(context.Background(), Selectors{}, func() {
			subWaitCh <- struct{}{}
		})
		if err != nil {
			subErrCh <- err
			return
		}

		defer sub1.Finish()

		u1 := <-sub1.Updates()
		if len(u1.Identities) > 0 {
			subErrCh <- fmt.Errorf("no identity expected, got: %d", len(u1.Identities))
			return
		}

		if len(u1.Bundle.X509Authorities()) != 1 {
			subErrCh <- fmt.Errorf("a single bundle is expected but got %d", len(u1.Bundle.X509Authorities()))
			return
		}

		if _, err := u1.Bundle.GetBundleForTrustDomain(trustDomain1); err != nil {
			subErrCh <- err
			return
		}

		subErrCh <- nil
	}()

	// Wait until subscriber is created and got a notification
	<-subWaitCh
	cache.SyncSVIDsWithSubscribers()

	assert.Len(t, cache.GetStaleEntries(), 1)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo, bar),
	})
	assert.Equal(t, 2, cache.CountSVIDs())

	select {
	case err := <-subErrCh:
		assert.NoError(t, err, "subscriber failed")
	case <-time.After(10 * time.Second):
		require.FailNow(t, "timed out waiting for notification")
	}
}

func TestSubscribeToLRUCacheChanges(t *testing.T) {
	clk := clock.NewMock(t)
	cache := newTestLRUCacheWithConfig(1, clk)

	foo := makeRegistrationEntry("FOO", "A")
	bar := makeRegistrationEntry("BAR", "B")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
	}, nil)

	sub1WaitCh := make(chan struct{}, 1)
	sub1ErrCh := make(chan error, 1)
	go func() {
		sub1, err := cache.subscribeToWorkloadUpdates(context.Background(), foo.Selectors, func() {
			sub1WaitCh <- struct{}{}
		})
		if err != nil {
			sub1ErrCh <- err
			return
		}

		defer sub1.Finish()
		u1 := <-sub1.Updates()
		if len(u1.Identities) != 1 {
			sub1ErrCh <- fmt.Errorf("expected 1 SVID, got: %d", len(u1.Identities))
			return
		}
		sub1ErrCh <- nil
	}()

	sub2WaitCh := make(chan struct{}, 1)
	sub2ErrCh := make(chan error, 1)
	go func() {
		sub2, err := cache.subscribeToWorkloadUpdates(context.Background(), bar.Selectors, func() {
			sub2WaitCh <- struct{}{}
		})
		if err != nil {
			sub2ErrCh <- err
			return
		}

		defer sub2.Finish()
		u2 := <-sub2.Updates()
		if len(u2.Identities) != 1 {
			sub1ErrCh <- fmt.Errorf("expected 1 SVID, got: %d", len(u2.Identities))
			return
		}
		sub2ErrCh <- nil
	}()

	<-sub1WaitCh
	<-sub2WaitCh
	cache.SyncSVIDsWithSubscribers()

	assert.Len(t, cache.GetStaleEntries(), 2)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo, bar),
	})
	assert.Equal(t, 2, cache.CountSVIDs())

	clk.WaitForAfter(time.Second, "waiting for after to get called")
	clk.Add(SVIDSyncInterval * 4)

	select {
	case sub1Err := <-sub1ErrCh:
		assert.NoError(t, sub1Err, "subscriber 1 error")
	case <-time.After(10 * time.Second):
		require.FailNow(t, "timed out waiting for SVID")
	}

	select {
	case sub2Err := <-sub2ErrCh:
		assert.NoError(t, sub2Err, "subscriber 2 error")
	case <-time.After(10 * time.Second):
		require.FailNow(t, "timed out waiting for SVID")
	}
}

func TestMetrics(t *testing.T) {
	cache := newTestLRUCache(t)
	fakeMetrics := fakemetrics.New()
	cache.metrics = fakeMetrics

	foo := makeRegistrationEntry("FOO", "A")
	bar := makeRegistrationEntry("BAR", "B")
	updateEntries := &UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
	}

	// add entries to cache
	cache.UpdateEntries(updateEntries, nil)
	assert.Equal(t, []fakemetrics.MetricItem{
		{Type: fakemetrics.IncrCounterType, Key: []string{telemetry.EntryRemoved}, Val: 0},
		{Type: fakemetrics.IncrCounterType, Key: []string{telemetry.EntryAdded}, Val: 2},
		{Type: fakemetrics.IncrCounterType, Key: []string{telemetry.EntryUpdated}, Val: 0},
		{Type: fakemetrics.SetGaugeType, Key: []string{telemetry.RecordMapSize}, Val: 2},
	}, fakeMetrics.AllMetrics())

	// add SVIDs to cache
	updateSVIDs := &UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	}
	cache.UpdateSVIDs(updateSVIDs)
	assert.Equal(t, []fakemetrics.MetricItem{
		{Type: fakemetrics.IncrCounterType, Key: []string{telemetry.EntryRemoved}, Val: 0},
		{Type: fakemetrics.IncrCounterType, Key: []string{telemetry.EntryAdded}, Val: 2},
		{Type: fakemetrics.IncrCounterType, Key: []string{telemetry.EntryUpdated}, Val: 0},
		{Type: fakemetrics.SetGaugeType, Key: []string{telemetry.RecordMapSize}, Val: 2},
		{Type: fakemetrics.SetGaugeType, Key: []string{telemetry.SVIDMapSize}, Val: 1},
	}, fakeMetrics.AllMetrics())

	// update entries in cache
	fooUpdate := makeRegistrationEntry("FOO", "A", "B")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(fooUpdate),
	}, nil)
	cache.UpdateEntries(updateEntries, nil)
	assert.Equal(t, []fakemetrics.MetricItem{
		{Type: fakemetrics.IncrCounterType, Key: []string{telemetry.EntryRemoved}, Val: 0},
		{Type: fakemetrics.IncrCounterType, Key: []string{telemetry.EntryAdded}, Val: 2},
		{Type: fakemetrics.IncrCounterType, Key: []string{telemetry.EntryUpdated}, Val: 0},
		{Type: fakemetrics.SetGaugeType, Key: []string{telemetry.RecordMapSize}, Val: 2},
		{Type: fakemetrics.SetGaugeType, Key: []string{telemetry.SVIDMapSize}, Val: 1},
		{Type: fakemetrics.IncrCounterType, Key: []string{telemetry.EntryRemoved}, Val: 1},
		{Type: fakemetrics.IncrCounterType, Key: []string{telemetry.EntryAdded}, Val: 0},
		{Type: fakemetrics.IncrCounterType, Key: []string{telemetry.EntryUpdated}, Val: 1},
		{Type: fakemetrics.SetGaugeType, Key: []string{telemetry.RecordMapSize}, Val: 1},
		{Type: fakemetrics.IncrCounterType, Key: []string{telemetry.EntryRemoved}, Val: 0},
		{Type: fakemetrics.IncrCounterType, Key: []string{telemetry.EntryAdded}, Val: 1},
		{Type: fakemetrics.IncrCounterType, Key: []string{telemetry.EntryUpdated}, Val: 1},
		{Type: fakemetrics.SetGaugeType, Key: []string{telemetry.RecordMapSize}, Val: 2},
	}, fakeMetrics.AllMetrics())
}

func TestNewLRUCache(t *testing.T) {
	// negative value
	cache := newTestLRUCacheWithConfig(-5, clock.NewMock(t))
	require.Equal(t, DefaultSVIDCacheMaxSize, cache.svidCacheMaxSize)

	// zero value
	cache = newTestLRUCacheWithConfig(0, clock.NewMock(t))
	require.Equal(t, DefaultSVIDCacheMaxSize, cache.svidCacheMaxSize)
}

func BenchmarkLRUCacheGlobalNotification(b *testing.B) {
	cache := newTestLRUCache(b)

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
		cache.NewSubscriber(selectors)
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

func newTestLRUCache(t testing.TB) *LRUCache {
	log, _ := test.NewNullLogger()
	return NewLRUCache(log, spiffeid.RequireTrustDomainFromString("domain.test"), bundleV1,
		telemetry.Blackhole{}, 0, clock.NewMock(t))
}

func newTestLRUCacheWithConfig(svidCacheMaxSize int, clk clock.Clock) *LRUCache {
	log, _ := test.NewNullLogger()
	return NewLRUCache(log, spiffeid.RequireTrustDomainFromString("domain.test"), bundleV1, telemetry.Blackhole{},
		svidCacheMaxSize, clk)
}

// numEntries should not be more than 12 digits
func createUpdateEntries(numEntries int, bundles map[spiffeid.TrustDomain]*spiffebundle.Bundle) *UpdateEntries {
	updateEntries := &UpdateEntries{
		Bundles:             bundles,
		RegistrationEntries: make(map[string]*common.RegistrationEntry, numEntries),
	}

	for i := 0; i < numEntries; i++ {
		entryID := fmt.Sprintf("00000000-0000-0000-0000-%012d", i)
		updateEntries.RegistrationEntries[entryID] = &common.RegistrationEntry{
			EntryId:   entryID,
			ParentId:  "spiffe://domain.test/node",
			SpiffeId:  fmt.Sprintf("spiffe://domain.test/workload-%d", i),
			Selectors: distinctSelectors(i, 1),
		}
	}
	return updateEntries
}

func makeX509SVIDsFromMap(entries map[string]*common.RegistrationEntry) map[string]*X509SVID {
	out := make(map[string]*X509SVID)
	for _, entry := range entries {
		out[entry.EntryId] = &X509SVID{}
	}
	return out
}

func makeX509SVIDsFromStaleEntries(entries []*StaleEntry) map[string]*X509SVID {
	out := make(map[string]*X509SVID)
	for _, entry := range entries {
		out[entry.Entry.EntryId] = &X509SVID{}
	}
	return out
}

func subscribeToWorkloadUpdates(t *testing.T, cache *LRUCache, selectors []*common.Selector) Subscriber {
	subscriber, err := cache.subscribeToWorkloadUpdates(context.Background(), selectors, nil)
	assert.NoError(t, err)
	return subscriber
}
