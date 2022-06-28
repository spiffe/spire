package cache

import (
	"crypto/x509"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
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
	foo := makeRegistrationEntry("FOO", "foo")
	bar := makeRegistrationEntry("BAR", "bar")
	bar.FederatesWith = makeFederatesWith(otherBundleV1)
	updateEntries := &UpdateEntries{
		Bundles:             makeBundles(bundleV1, otherBundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
	}
	cache.UpdateEntries(updateEntries, nil)

	workloadUpdate := cache.FetchWorkloadUpdate(makeSelectors("foo", "bar"))
	assert.Len(t, workloadUpdate.Identities, 0, "identities should not be returned that don't have SVIDs")

	updateSVIDs := &UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo, bar),
	}
	cache.UpdateSVIDs(updateSVIDs)

	workloadUpdate = cache.FetchWorkloadUpdate(makeSelectors("foo", "bar"))
	assert.Equal(t, &WorkloadUpdate{
		Bundle:           bundleV1,
		FederatedBundles: makeBundles(otherBundleV1),
		Identities: []Identity{
			{Entry: bar},
			{Entry: foo},
		},
	}, workloadUpdate)
}

func TestMatchingRegistrationIdentities(t *testing.T) {
	cache := newTestCache()

	// populate the cache with FOO and BAR without SVIDS
	foo := makeRegistrationEntry("FOO", "foo")
	bar := makeRegistrationEntry("BAR", "bar")
	updateEntries := &UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
	}
	cache.UpdateEntries(updateEntries, nil)

	assert.Equal(t, []*common.RegistrationEntry{bar, foo},
		cache.MatchingRegistrationEntries(makeSelectors("foo", "bar")))

	// Update SVIDs and MatchingRegistrationEntries should return both entries
	updateSVIDs := &UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo, bar),
	}
	cache.UpdateSVIDs(updateSVIDs)
	assert.Equal(t, []*common.RegistrationEntry{bar, foo},
		cache.MatchingRegistrationEntries(makeSelectors("foo", "bar")))

	// Remove SVIDs and MatchingRegistrationEntries should still return both entries
	cache.UpdateSVIDs(&UpdateSVIDs{})
	assert.Equal(t, []*common.RegistrationEntry{bar, foo},
		cache.MatchingRegistrationEntries(makeSelectors("foo", "bar")))
}

func TestCountSVIDs(t *testing.T) {
	cache := newTestCache()

	// populate the cache with FOO and BAR without SVIDS
	foo := makeRegistrationEntry("FOO", "foo")
	bar := makeRegistrationEntry("BAR", "bar")
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
	subFoo := subscribeToWorkloadUpdatesAndNotify(t, cache, makeSelectors("foo"))
	defer subFoo.Finish()
	assertWorkloadUpdateEqual(t, subFoo, &WorkloadUpdate{Bundle: bundleV1})

	subBar := subscribeToWorkloadUpdatesAndNotify(t, cache, makeSelectors("bar"))
	defer subBar.Finish()
	assertWorkloadUpdateEqual(t, subBar, &WorkloadUpdate{Bundle: bundleV1})

	// update the bundle and assert all subscribers gets the updated bundle
	cache.UpdateEntries(&UpdateEntries{
		Bundles: makeBundles(bundleV2),
	}, nil)
	assertWorkloadUpdateEqual(t, subFoo, &WorkloadUpdate{Bundle: bundleV2})
	assertWorkloadUpdateEqual(t, subBar, &WorkloadUpdate{Bundle: bundleV2})
}

func TestSomeSubscribersNotifiedOnFederatedBundleChange(t *testing.T) {
	cache := newTestCache()

	// initialize the cache with an entry FOO that has a valid SVID and
	// selector "foo"
	foo := makeRegistrationEntry("FOO", "foo")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})

	// subscribe to A and B and assert initial updates are received.
	subFoo := subscribeToWorkloadUpdatesAndNotify(t, cache, makeSelectors("foo"))
	defer subFoo.Finish()
	assertAnyWorkloadUpdate(t, subFoo)

	subBar := subscribeToWorkloadUpdatesAndNotify(t, cache, makeSelectors("bar"))
	defer subBar.Finish()
	assertAnyWorkloadUpdate(t, subBar)

	// add the federated bundle with no registration entries federating with
	// it and make sure nobody is notified.
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1, otherBundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	assertNoWorkloadUpdate(t, subFoo)
	assertNoWorkloadUpdate(t, subBar)

	// update FOO to federate with otherdomain.test and make sure subFoo is
	// notified but not subBar.
	foo = makeRegistrationEntry("FOO", "foo")
	foo.FederatesWith = makeFederatesWith(otherBundleV1)
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1, otherBundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	assertWorkloadUpdateEqual(t, subFoo, &WorkloadUpdate{
		Bundle:           bundleV1,
		FederatedBundles: makeBundles(otherBundleV1),
		Identities:       []Identity{{Entry: foo}},
	})
	assertNoWorkloadUpdate(t, subBar)

	// now change the federated bundle and make sure subFoo gets notified, but
	// again, not subBar.
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1, otherBundleV2),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	assertWorkloadUpdateEqual(t, subFoo, &WorkloadUpdate{
		Bundle:           bundleV1,
		FederatedBundles: makeBundles(otherBundleV2),
		Identities:       []Identity{{Entry: foo}},
	})
	assertNoWorkloadUpdate(t, subBar)

	// now drop the federation and make sure subFoo is again notified and no
	// longer has the federated bundle.
	foo = makeRegistrationEntry("FOO", "foo")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1, otherBundleV2),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	assertWorkloadUpdateEqual(t, subFoo, &WorkloadUpdate{
		Bundle:     bundleV1,
		Identities: []Identity{{Entry: foo}},
	})
	assertNoWorkloadUpdate(t, subBar)
}

func TestSubscribersGetEntriesWithSelectorSubsets(t *testing.T) {
	cache := newTestCache()

	// create subscribers for each combination of selectors
	subFoo := subscribeToWorkloadUpdatesAndNotify(t, cache, makeSelectors("foo"))
	defer subFoo.Finish()
	subBar := subscribeToWorkloadUpdatesAndNotify(t, cache, makeSelectors("bar"))
	defer subBar.Finish()
	subFooBar := subscribeToWorkloadUpdatesAndNotify(t, cache, makeSelectors("foo", "bar"))
	defer subFooBar.Finish()

	// assert all subscribers get the initial update
	initialUpdate := &WorkloadUpdate{Bundle: bundleV1}
	assertWorkloadUpdateEqual(t, subFoo, initialUpdate)
	assertWorkloadUpdateEqual(t, subBar, initialUpdate)
	assertWorkloadUpdateEqual(t, subFooBar, initialUpdate)

	// create entry FOO that will target any subscriber with containing (foo)
	foo := makeRegistrationEntry("FOO", "foo")

	// create entry BAR that will target any subscriber with containing (foo,baz)
	bar := makeRegistrationEntry("BAR", "foo", "baz")

	// update the cache with foo and bar
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
	}, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo, bar),
	})

	// subFoo selector set contains (foo), but not (foo, baz), so it should only get FOO
	assertWorkloadUpdateEqual(t, subFoo, &WorkloadUpdate{
		Bundle:     bundleV1,
		Identities: []Identity{{Entry: foo}},
	})

	// subBar selector set does not contain either (foo) or (foo,baz) so it isn't even
	// notified.
	assertNoWorkloadUpdate(t, subBar)

	// subFooBar selector set contains (foo) but not (foo, baz), so it should get FOO
	assertWorkloadUpdateEqual(t, subFooBar, &WorkloadUpdate{
		Bundle:     bundleV1,
		Identities: []Identity{{Entry: foo}},
	})
}

func TestSubscriberIsNotNotifiedIfNothingChanges(t *testing.T) {
	cache := newTestCache()

	foo := makeRegistrationEntry("FOO", "foo")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})

	sub := subscribeToWorkloadUpdatesAndNotify(t, cache, makeSelectors("foo"))
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

	foo := makeRegistrationEntry("FOO", "foo")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})

	sub := subscribeToWorkloadUpdatesAndNotify(t, cache, makeSelectors("foo"))
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

func TestSubscriberNotificationsOnSelectorChanges(t *testing.T) {
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
	sub := subscribeToWorkloadUpdatesAndNotify(t, cache, makeSelectors("A"))
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

func TestSubscriberNotifiedWhenEntryDropped(t *testing.T) {
	cache := newTestCache()

	subFoo := subscribeToWorkloadUpdatesAndNotify(t, cache, makeSelectors("foo"))
	defer subFoo.Finish()
	assertAnyWorkloadUpdate(t, subFoo)

	// subBar's job here is to just make sure we don't notify unrelated
	// subscribers when dropping registration entries
	subBar := subscribeToWorkloadUpdatesAndNotify(t, cache, makeSelectors("bar"))
	defer subBar.Finish()
	assertAnyWorkloadUpdate(t, subBar)

	foo := makeRegistrationEntry("FOO", "foo")
	updateEntries := &UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}
	cache.UpdateEntries(updateEntries, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})
	// make sure subFoo gets notified with FOO but not subBar
	assertWorkloadUpdateEqual(t, subFoo, &WorkloadUpdate{
		Bundle:     bundleV1,
		Identities: []Identity{{Entry: foo}},
	})
	assertNoWorkloadUpdate(t, subBar)

	updateEntries.RegistrationEntries = nil
	cache.UpdateEntries(updateEntries, nil)
	assertWorkloadUpdateEqual(t, subFoo, &WorkloadUpdate{
		Bundle: bundleV1,
	})
	assertNoWorkloadUpdate(t, subBar)

	// Make sure trying to update SVIDs of removed entry does not notify
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})
	assertNoWorkloadUpdate(t, subBar)
}

func TestSubscriberOnlyGetsEntriesWithSVID(t *testing.T) {
	cache := newTestCache()

	foo := makeRegistrationEntry("FOO", "foo")
	updateEntries := &UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}
	cache.UpdateEntries(updateEntries, nil)

	subFoo := cache.SubscribeToWorkloadUpdates(makeSelectors("foo"))
	defer subFoo.Finish()
	assertNoWorkloadUpdate(t, subFoo)

	// update to include the SVID and now we should get the update
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})
	assertWorkloadUpdateEqual(t, subFoo, &WorkloadUpdate{
		Bundle:     bundleV1,
		Identities: []Identity{{Entry: foo}},
	})
}

func TestSubscribersDoNotBlockNotifications(t *testing.T) {
	cache := newTestCache()

	subFoo := subscribeToWorkloadUpdatesAndNotify(t, cache, makeSelectors("foo"))
	defer subFoo.Finish()

	cache.UpdateEntries(&UpdateEntries{
		Bundles: makeBundles(bundleV2),
	}, nil)

	cache.UpdateEntries(&UpdateEntries{
		Bundles: makeBundles(bundleV3),
	}, nil)

	assertWorkloadUpdateEqual(t, subFoo, &WorkloadUpdate{
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

func TestGetStaleEntries(t *testing.T) {
	cache := newTestCache()

	foo := makeRegistrationEntryWithTTL("FOO", 60)
	expiredAt := time.Now()

	// Create entry but don't mark it stale from checkSVID method;
	// it will be marked stale cause it does not have SVID cached
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV2),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, func(existingEntry, newEntry *common.RegistrationEntry, svid *X509SVID) bool {
		return false
	})

	// Assert that the entry is returned as stale. The `ExpiresAt` field should be unset since there is no SVID.
	expectedEntries := []*StaleEntry{{Entry: cache.records[foo.EntryId].entry}}
	assert.Equal(t, expectedEntries, cache.GetStaleEntries())

	// Update the SVID for the stale entry
	svids := make(map[string]*X509SVID)
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

func TestSubscriberNotNotifiedOnDifferentSVIDChanges(t *testing.T) {
	cache := newTestCache()

	foo := makeRegistrationEntry("FOO", "foo")
	bar := makeRegistrationEntry("BAR", "bar")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
	}, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo, bar),
	})

	sub := subscribeToWorkloadUpdatesAndNotify(t, cache, makeSelectors("foo"))
	defer sub.Finish()
	assertAnyWorkloadUpdate(t, sub)

	// Update SVID
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(bar),
	})

	assertNoWorkloadUpdate(t, sub)
}

func TestSubscriberNotNotifiedOnOverlappingSVIDChanges(t *testing.T) {
	cache := newTestCache()

	foo := makeRegistrationEntry("FOO", "A", "C")
	bar := makeRegistrationEntry("FOO", "A", "B")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo, bar),
	})

	sub := subscribeToWorkloadUpdatesAndNotify(t, cache, makeSelectors("A", "B"))
	defer sub.Finish()
	assertAnyWorkloadUpdate(t, sub)

	// Update SVID
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})

	assertNoWorkloadUpdate(t, sub)
}

func TestSVIDCacheExpiry(t *testing.T) {
	clk := clock.NewMock()
	cache := newTestCacheWithConfig(10, 1*time.Minute, clk)

	clk.Add(1 * time.Second)
	foo := makeRegistrationEntry("FOO", "foo")
	// validate workload update for foo
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})
	subFoo := subscribeToWorkloadUpdatesAndNotify(t, cache, makeSelectors("foo"))
	assertWorkloadUpdateEqual(t, subFoo, &WorkloadUpdate{
		Bundle:     bundleV1,
		Identities: []Identity{{Entry: foo}},
	})
	subFoo.Finish()

	// move clk by 1 sec so that SVID access time will be different
	clk.Add(1 * time.Second)
	bar := makeRegistrationEntry("BAR", "bar")
	// validate workload update for bar
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
	}, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(bar),
	})

	// not closing subscriber immediately
	subBar := subscribeToWorkloadUpdatesAndNotify(t, cache, makeSelectors("bar"))
	defer subBar.Finish()
	assertWorkloadUpdateEqual(t, subBar, &WorkloadUpdate{
		Bundle: bundleV1,
		Identities: []Identity{
			{Entry: bar},
		},
	})

	// Move clk by a second
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
			sub := cache.SubscribeToWorkloadUpdates(entry.Selectors)
			sub.Finish()
		}
	}

	// Move clk by 58 sec so that a minute has passed since last foo was accessed
	// svid for foo should be deleted
	clk.Add(58 * time.Second)
	cache.UpdateEntries(updateEntries, nil)

	subFoo = cache.SubscribeToWorkloadUpdates(makeSelectors("foo"))
	defer subFoo.Finish()
	assert.False(t, cache.Notify(makeSelectors("foo")))
	assert.Equal(t, 11, cache.CountSVIDs())

	// move clk by another minute and update entries
	clk.Add(1 * time.Minute)
	cache.UpdateEntries(updateEntries, nil)

	// Make sure foo is marked as stale entry which does not have svid cached
	require.Len(t, cache.GetStaleEntries(), 1)
	assert.Equal(t, foo, cache.GetStaleEntries()[0].Entry)

	// bar should not be removed from cache as it has another active subscriber
	subBar2 := subscribeToWorkloadUpdatesAndNotify(t, cache, makeSelectors("bar"))
	defer subBar2.Finish()
	assertWorkloadUpdateEqual(t, subBar2, &WorkloadUpdate{
		Bundle: bundleV1,
		Identities: []Identity{
			{Entry: bar},
		},
	})

	// ensure SVIDs without active subscribers are still cached for remainder of cache size
	assert.Equal(t, 10, cache.CountSVIDs())
}

func TestMaxSVIDCacheSize(t *testing.T) {
	clk := clock.NewMock()
	cache := newTestCacheWithConfig(10, 1*time.Minute, clk)

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
	foo := makeRegistrationEntry("FOO", "foo")
	updateEntries.RegistrationEntries[foo.EntryId] = foo

	subFoo := cache.SubscribeToWorkloadUpdates(foo.Selectors)
	defer subFoo.Finish()

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
	clk := clock.NewMock()
	cache := newTestCacheWithConfig(5, 1*time.Minute, clk)

	updateEntries := createUpdateEntries(5, makeBundles(bundleV1))
	cache.UpdateEntries(updateEntries, nil)
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDsFromStaleEntries(cache.GetStaleEntries()),
	})
	assert.Equal(t, 5, cache.CountSVIDs())

	// Update foo but its SVID is not yet cached
	foo := makeRegistrationEntry("FOO", "foo")
	updateEntries.RegistrationEntries[foo.EntryId] = foo

	cache.UpdateEntries(updateEntries, nil)

	// Create a subscriber for foo
	subFoo := cache.SubscribeToWorkloadUpdates(foo.Selectors)
	defer subFoo.Finish()
	require.Len(t, cache.GetStaleEntries(), 0)

	// After SyncSVIDsWithSubscribers foo should be marked as stale, requiring signing
	cache.SyncSVIDsWithSubscribers()
	require.Len(t, cache.GetStaleEntries(), 1)
	assert.Equal(t, []*StaleEntry{{Entry: cache.records[foo.EntryId].entry}}, cache.GetStaleEntries())

	assert.Equal(t, 5, cache.CountSVIDs())
}

func TestNotify(t *testing.T) {
	cache := newTestCache()

	foo := makeRegistrationEntry("FOO", "foo")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)

	assert.False(t, cache.Notify(makeSelectors("foo")))
	cache.UpdateSVIDs(&UpdateSVIDs{
		X509SVIDs: makeX509SVIDs(foo),
	})
	assert.True(t, cache.Notify(makeSelectors("foo")))
}

func TestNewCache(t *testing.T) {
	// negative values
	cache := newTestCacheWithConfig(-5, -5, clock.NewMock())
	require.Equal(t, DefaultMaxSvidCacheSize, cache.maxSvidCacheSize)
	require.Equal(t, DefaultSVIDCacheExpiryPeriod, cache.svidCacheExpiryPeriod)

	// zero values
	cache = newTestCacheWithConfig(0, 0, clock.NewMock())
	require.Equal(t, DefaultMaxSvidCacheSize, cache.maxSvidCacheSize)
	require.Equal(t, DefaultSVIDCacheExpiryPeriod, cache.svidCacheExpiryPeriod)
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

func newTestCache() *Cache {
	log, _ := test.NewNullLogger()
	return New(log, spiffeid.RequireTrustDomainFromString("domain.test"), bundleV1,
		telemetry.Blackhole{}, 0, 0, clock.NewMock())
}

func newTestCacheWithConfig(maxSvidCacheSize int, svidCacheExpiryPeriod time.Duration, clk clock.Clock) *Cache {
	log, _ := test.NewNullLogger()
	return New(log, spiffeid.RequireTrustDomainFromString("domain.test"), bundleV1, telemetry.Blackhole{},
		maxSvidCacheSize, svidCacheExpiryPeriod, clk)
}

// numEntries should not be more than 12 digits
func createUpdateEntries(numEntries int, bundles map[spiffeid.TrustDomain]*bundleutil.Bundle) *UpdateEntries {
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

func subscribeToWorkloadUpdatesAndNotify(t *testing.T, cache *Cache, selectors []*common.Selector) Subscriber {
	subscriber := cache.SubscribeToWorkloadUpdates(selectors)
	assert.True(t, cache.Notify(selectors))
	return subscriber
}
