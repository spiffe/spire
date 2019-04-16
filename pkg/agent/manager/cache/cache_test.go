package cache

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	testlog "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	privateKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	logger        logrus.FieldLogger
)

func init() {
	l, _ := testlog.NewNullLogger()
	logger = l.WithField("subsystem_name", "manager")
}

func TestCacheImpl_Valid(t *testing.T) {
	cache := New(logger, "spiffe://example.org", nil)
	tests := []struct {
		name string
		ce   *Entry
	}{
		{name: "test_single_selector",
			ce: &Entry{
				RegistrationEntry: &common.RegistrationEntry{
					Selectors: Selectors{&common.Selector{Type: "testtype", Value: "testValue"}},
					ParentId:  "spiffe:parent",
					SpiffeId:  "spiffe:test",
				},
				SVID:       []*x509.Certificate{{}},
				PrivateKey: privateKey,
			}},

		{name: "test_multiple_selectors_sort_same_type",
			ce: &Entry{
				RegistrationEntry: &common.RegistrationEntry{
					Selectors: Selectors{&common.Selector{Type: "testtype3", Value: "testValue1"},
						&common.Selector{Type: "testtype1", Value: "testValue2"},
						&common.Selector{Type: "testtype1", Value: "testValue3"}},
					ParentId: "spiffe:parent",
					SpiffeId: "spiffe:test"},
				SVID:       []*x509.Certificate{{}},
				PrivateKey: privateKey,
			}}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cache.SetEntry(test.ce)
			actual := cache.FetchEntry(test.ce.RegistrationEntry.EntryId)
			assert.Equal(t, actual, test.ce)

		})
	}
}

func TestCacheImpl_DeleteEntry(t *testing.T) {
	cache := New(logger, "spiffe://example.org", nil)
	tests := []struct {
		name string
		ce   *Entry
	}{
		{name: "test_single_selector",
			ce: &Entry{
				RegistrationEntry: &common.RegistrationEntry{
					Selectors: Selectors{&common.Selector{Type: "testtype", Value: "testValue"}},
					ParentId:  "spiffe:parent",
					SpiffeId:  "spiffe:test"},
				SVID:       []*x509.Certificate{{}},
				PrivateKey: privateKey,
			}},

		{name: "test_multiple_selectors",
			ce: &Entry{
				RegistrationEntry: &common.RegistrationEntry{
					Selectors: Selectors{&common.Selector{Type: "testtype3", Value: "testValue1"},
						&common.Selector{Type: "testtype2", Value: "testValue2"},
						&common.Selector{Type: "testtype1", Value: "testValue3"}},
					ParentId: "spiffe:parent",
					SpiffeId: "spiffe:test"},
				SVID:       []*x509.Certificate{{}},
				PrivateKey: privateKey,
			}}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cache.SetEntry(test.ce)
			deleted := cache.DeleteEntry(test.ce.RegistrationEntry)
			assert.True(t, deleted)
			entry := cache.FetchEntry(test.ce.RegistrationEntry.EntryId)
			assert.Empty(t, entry)
			deleted = cache.DeleteEntry(test.ce.RegistrationEntry)
			assert.False(t, deleted)

		})
	}
}

func TestNotifySubscribersDoesntBlockOnSubscriberWrite(t *testing.T) {
	cache := New(logger, "spiffe://example.org", nil)

	exampleBundle := bundleutil.BundleFromRootCAs("spiffe://example.org", []*x509.Certificate{{Raw: []byte("EXAMPLE.ORG")}})
	otherDomainBundle := bundleutil.BundleFromRootCAs("spiffe://otherdomain.test", []*x509.Certificate{{Raw: []byte("OTHERDOMAIN.TEST")}})

	cache.SetBundles(map[string]*Bundle{
		"spiffe://example.org":      exampleBundle,
		"spiffe://otherdomain.test": otherDomainBundle,
	})

	e1 := &Entry{
		RegistrationEntry: &common.RegistrationEntry{
			Selectors: Selectors{
				&common.Selector{Type: "unix", Value: "uid:1000"},
			},
			ParentId: "spiffe:parent1",
			SpiffeId: "spiffe:test1",
			EntryId:  "00000000-0000-0000-0000-000000000001",
		},
		SVID:       []*x509.Certificate{{}},
		PrivateKey: privateKey,
	}
	cache.SetEntry(e1)

	e2 := &Entry{
		RegistrationEntry: &common.RegistrationEntry{
			Selectors: Selectors{
				&common.Selector{Type: "unix", Value: "uid:1111"},
			},
			ParentId:      "spiffe:parent2",
			SpiffeId:      "spiffe:test2",
			EntryId:       "00000000-0000-0000-0000-000000000002",
			FederatesWith: []string{"spiffe://otherdomain.test"},
		},
		SVID:       []*x509.Certificate{{}},
		PrivateKey: privateKey,
	}
	cache.SetEntry(e2)

	sub1, err := NewSubscriber(Selectors{&common.Selector{Type: "unix", Value: "uid:1111"}})
	assert.Nil(t, err)

	sub2, err := NewSubscriber(Selectors{&common.Selector{Type: "unix", Value: "uid:1000"}})
	assert.Nil(t, err)

	cache.notifySubscribers([]*subscriber{sub1, sub2})

	util.RunWithTimeout(t, 5*time.Second, func() {
		wu := <-sub2.Updates()
		assert.Equal(t, 1, len(wu.Entries))
		assert.Equal(t, e1, wu.Entries[0])
		assert.Equal(t, exampleBundle, wu.Bundle)
	})

	// The second registration entry federates with otherdomain.test. The
	// WorkloadUpdate should include that bundle.
	util.RunWithTimeout(t, 5*time.Second, func() {
		wu := <-sub1.Updates()
		assert.Equal(t, 1, len(wu.Entries))
		assert.Equal(t, e2, wu.Entries[0])
		assert.Equal(t, exampleBundle, wu.Bundle)
		assert.Equal(t, map[string]*Bundle{
			"spiffe://otherdomain.test": otherDomainBundle,
		}, wu.FederatedBundles)
	})
}

func TestNotifySubscribersDoesntPileUpGoroutines(t *testing.T) {
	cache := New(logger, "spiffe://example.org", nil)

	e2 := &Entry{
		RegistrationEntry: &common.RegistrationEntry{
			Selectors: Selectors{
				&common.Selector{Type: "unix", Value: "uid:1111"},
			},
			ParentId: "spiffe:parent2",
			SpiffeId: "spiffe:test2",
			EntryId:  "00000000-0000-0000-0000-000000000002",
		},
		SVID:       []*x509.Certificate{{}},
		PrivateKey: privateKey,
	}
	cache.SetEntry(e2)

	sub1, err := NewSubscriber(Selectors{&common.Selector{Type: "unix", Value: "uid:1111"}})
	assert.Nil(t, err)

	util.RunWithTimeout(t, 5*time.Second, func() {
		ng := runtime.NumGoroutine()
		for i := 0; i < 1000; i++ {
			cache.notifySubscribers([]*subscriber{sub1})
			assert.True(t, runtime.NumGoroutine() <= ng)
		}
	})
}

func TestNotifySubscribersNotifiesLatestUpdatesToSlowSubscriber(t *testing.T) {
	cache := New(logger, "spiffe://example.org", nil)

	sub := cache.Subscribe(Selectors{&common.Selector{Type: "unix", Value: "uid:1111"}})

	var wg sync.WaitGroup
	// Shared counter to keep track of number of updates made.
	var i int32

	// This go routine send updates notifications as fast as it can.
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Use of atomic functions to avoid race condition.
		for atomic.StoreInt32(&i, 0); atomic.LoadInt32(&i) < 1000; atomic.AddInt32(&i, 1) {
			e := &Entry{
				RegistrationEntry: &common.RegistrationEntry{
					Selectors: Selectors{
						&common.Selector{Type: "unix", Value: "uid:1111"},
					},
					ParentId: "spiffe:parent2",
					// We set a numeric (crescent by 1) suffix to the spiffe id to know at
					// the receiver if we are getting updates in the correct order.
					SpiffeId: fmt.Sprintf("spiffe:test2_%d", i),
					EntryId:  "00000000-0000-0000-0000-000000000002",
				},
				SVID:       []*x509.Certificate{{}},
				PrivateKey: privateKey,
			}
			// SetEntry updates the cache entry and fires a notification for the subscribers
			// that match the entry's selectors.
			cache.SetEntry(e)
		}
	}()

	// This go routine reads the updates slowly and checks if it receives the updates
	// in order.
	wg.Add(1)
	go func() {
		defer wg.Done()
		var lastSuffix int = -1
		// Loop while the writer didn't finished writing updates or there are some update
		// left. This way we ensure this go routine will read the last update sent by the writer.
		for atomic.LoadInt32(&i) != 1000 || len(sub.Updates()) != 0 {
			wu := <-sub.Updates()
			if len(wu.Entries) == 1 {
				// Get the SpiffeId's numeric suffix
				parts := strings.Split(wu.Entries[0].RegistrationEntry.SpiffeId, "_")
				currentSuffix, _ := strconv.Atoi(parts[1])
				// SpiffeId suffixes should be always increasing, if they aren't
				// it means we are receiving unordered updates.
				assert.True(t, lastSuffix < currentSuffix)
				lastSuffix = currentSuffix
				// We sleep a bit to make this a slow reader.
				time.Sleep(2 * time.Millisecond)
			}
		}
		// Assert that we got the last update
		assert.Equal(t, 999, lastSuffix)
	}()

	wg.Wait()
}

func TestSubscriberFinish(t *testing.T) {
	cache := New(logger, "spiffe://example.org", nil)

	sub := cache.Subscribe(Selectors{&common.Selector{Type: "unix", Value: "uid:1111"}})

	// Comsume the update sent by Subscribe function.
	<-sub.Updates()

	sub.Finish()

	// This read shouldn't block.
	util.RunWithTimeout(t, 5*time.Second, func() {
		wu := <-sub.Updates()
		assert.Nil(t, wu)
	})

	// SetEntry will notify updates, but our subscriber shouldn't get any because it is finished.
	cache.SetEntry(&Entry{
		RegistrationEntry: &common.RegistrationEntry{
			Selectors: Selectors{
				&common.Selector{Type: "unix", Value: "uid:1111"},
			},
			ParentId: "spiffe:parent2",
			SpiffeId: "spiffe:test2",
			EntryId:  "00000000-0000-0000-0000-000000000002",
		},
		SVID:       []*x509.Certificate{{}},
		PrivateKey: privateKey,
	})

	util.RunWithTimeout(t, 5*time.Second, func() {
		wu := <-sub.Updates()
		assert.Nil(t, wu)
	})
}

func TestFetchWorkloadUpdate(t *testing.T) {
	one := &Entry{
		RegistrationEntry: &common.RegistrationEntry{
			EntryId:   "1",
			Selectors: Selectors{{Type: "A", Value: "a"}},
			ParentId:  "spiffe:parent",
			SpiffeId:  "spiffe:id1",
		},
	}
	two := &Entry{
		RegistrationEntry: &common.RegistrationEntry{
			EntryId: "2",
			Selectors: Selectors{
				{Type: "A", Value: "a"},
				{Type: "B", Value: "b"},
				{Type: "C", Value: "c"},
			},
			ParentId:      "spiffe:parent",
			SpiffeId:      "spiffe:id2",
			FederatesWith: []string{"spiffe://bar.test"},
		},
	}

	cache := New(logger, "spiffe://example.org", nil)
	cache.SetBundles(map[string]*Bundle{
		"spiffe://example.org": {},
		"spiffe://foo.test":    {},
		"spiffe://bar.test":    {},
	})
	cache.SetEntry(one)
	cache.SetEntry(two)

	// selectors don't match anything
	update := cache.FetchWorkloadUpdate(Selectors{})
	require.NotNil(t, update)
	assert.Empty(t, update.Entries)

	// selectors match one
	update = cache.FetchWorkloadUpdate(Selectors{{Type: "A", Value: "a"}})
	require.NotNil(t, update)
	sortCacheEntries(update.Entries)
	assert.Equal(t, []*Entry{one}, update.Entries)
	assert.NotNil(t, update.Bundle)
	assert.Empty(t, update.FederatedBundles)

	// selectors match one and two
	update = cache.FetchWorkloadUpdate(Selectors{
		{Type: "A", Value: "a"},
		{Type: "B", Value: "b"},
		{Type: "C", Value: "c"},
	})
	require.NotNil(t, update)
	sortCacheEntries(update.Entries)
	assert.Equal(t, []*Entry{one, two}, update.Entries)
	assert.NotNil(t, update.Bundle)
	assert.Len(t, update.FederatedBundles, 1)
	assert.NotNil(t, update.FederatedBundles["spiffe://bar.test"])
}

func TestJWTSVID(t *testing.T) {
	now := time.Now()
	expected := &client.JWTSVID{Token: "X", IssuedAt: now, ExpiresAt: now.Add(time.Second)}

	cache := New(logger, "spiffe://example.org", nil)

	// JWT is not cached
	actual, ok := cache.GetJWTSVID("spiffe://example.org/blog", []string{"bar"})
	assert.False(t, ok)
	assert.Nil(t, actual)

	// JWT is cached
	cache.SetJWTSVID("spiffe://example.org/blog", []string{"bar"}, expected)
	actual, ok = cache.GetJWTSVID("spiffe://example.org/blog", []string{"bar"})
	assert.True(t, ok)
	assert.Equal(t, expected, actual)
}

func sortCacheEntries(entries []*Entry) {
	sort.Slice(entries, func(a, b int) bool {
		return entries[a].RegistrationEntry.EntryId < entries[b].RegistrationEntry.EntryId
	})
}
