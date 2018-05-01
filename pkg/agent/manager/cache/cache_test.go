package cache

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"github.com/spiffe/spire/test/util"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	testlog "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/proto/common"
	"github.com/stretchr/testify/assert"
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
	cache := New(logger, nil)
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
				SVID:       &x509.Certificate{},
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
				SVID:       &x509.Certificate{},
				PrivateKey: privateKey,
			}}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cache.SetEntry(test.ce)
			actual := cache.Entry(test.ce.RegistrationEntry)
			assert.Equal(t, actual, test.ce)

		})
	}
}

func TestCacheImpl_Invalid(t *testing.T) {
	cache := New(logger, nil)
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
					EntryId:   "00000000-0000-0000-0000-000000000000",
				},
				SVID:       &x509.Certificate{},
				PrivateKey: privateKey,
			}},

		{name: "test_multiple_selectors_sort_different_types",
			ce: &Entry{
				RegistrationEntry: &common.RegistrationEntry{
					Selectors: Selectors{&common.Selector{Type: "testtype3", Value: "testValue1"},
						&common.Selector{Type: "testtype2", Value: "testValue2"},
						&common.Selector{Type: "testtype1", Value: "testValue3"}},
					ParentId: "spiffe:parent",
					SpiffeId: "spiffe:test",
					EntryId:  "00000000-0000-0000-0000-000000000001",
				},
				SVID:       &x509.Certificate{},
				PrivateKey: privateKey,
			}}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cache.SetEntry(test.ce)
			actual := cache.Entry(&common.RegistrationEntry{
				Selectors: Selectors{&common.Selector{Type: "invalid", Value: "testValue1"}},
			})
			assert.Empty(t, actual)
		})
	}
}

func TestCacheImpl_DeleteEntry(t *testing.T) {
	cache := New(logger, nil)
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
				SVID:       &x509.Certificate{},
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
				SVID:       &x509.Certificate{},
				PrivateKey: privateKey,
			}}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cache.SetEntry(test.ce)
			deleted := cache.DeleteEntry(test.ce.RegistrationEntry)
			assert.True(t, deleted)
			entry := cache.Entry(test.ce.RegistrationEntry)
			assert.Empty(t, entry)
			deleted = cache.DeleteEntry(test.ce.RegistrationEntry)
			assert.False(t, deleted)

		})
	}
}

func TestNotifySubscribersDoesntBlockOnSubscriberWrite(t *testing.T) {
	cache := New(logger, nil)

	e1 := &Entry{
		RegistrationEntry: &common.RegistrationEntry{
			Selectors: Selectors{
				&common.Selector{Type: "unix", Value: "uid:1000"},
			},
			ParentId: "spiffe:parent1",
			SpiffeId: "spiffe:test1",
			EntryId:  "00000000-0000-0000-0000-000000000001",
		},
		SVID:       &x509.Certificate{},
		PrivateKey: privateKey,
	}
	cache.SetEntry(e1)

	e2 := &Entry{
		RegistrationEntry: &common.RegistrationEntry{
			Selectors: Selectors{
				&common.Selector{Type: "unix", Value: "uid:1111"},
			},
			ParentId: "spiffe:parent2",
			SpiffeId: "spiffe:test2",
			EntryId:  "00000000-0000-0000-0000-000000000002",
		},
		SVID:       &x509.Certificate{},
		PrivateKey: privateKey,
	}
	cache.SetEntry(e2)

	sub1, err := NewSubscriber(Selectors{&common.Selector{Type: "unix", Value: "uid:1111"}})
	assert.Nil(t, err)

	sub2, err := NewSubscriber(Selectors{&common.Selector{Type: "unix", Value: "uid:1000"}})
	assert.Nil(t, err)

	cache.notifySubscribers([]*Subscriber{sub1, sub2})

	util.RunWithTimeout(t, 5*time.Second, func() {
		wu := <-sub2.Updates()
		assert.Equal(t, 1, len(wu.Entries))
		assert.Equal(t, e1, wu.Entries[0])
	})

	util.RunWithTimeout(t, 5*time.Second, func() {
		wu := <-sub1.Updates()
		assert.Equal(t, 1, len(wu.Entries))
		assert.Equal(t, e2, wu.Entries[0])
	})
}

func TestNotifySubscribersDoesntPileUpGoroutines(t *testing.T) {
	cache := New(logger, nil)

	e2 := &Entry{
		RegistrationEntry: &common.RegistrationEntry{
			Selectors: Selectors{
				&common.Selector{Type: "unix", Value: "uid:1111"},
			},
			ParentId: "spiffe:parent2",
			SpiffeId: "spiffe:test2",
			EntryId:  "00000000-0000-0000-0000-000000000002",
		},
		SVID:       &x509.Certificate{},
		PrivateKey: privateKey,
	}
	cache.SetEntry(e2)

	sub1, err := NewSubscriber(Selectors{&common.Selector{Type: "unix", Value: "uid:1111"}})
	assert.Nil(t, err)

	util.RunWithTimeout(t, 5*time.Second, func() {
		ng := runtime.NumGoroutine()
		for i := 0; i < 1000; i++ {
			cache.notifySubscribers([]*Subscriber{sub1})
			assert.Equal(t, ng, runtime.NumGoroutine())
		}
	})
}

func TestNotifySubscribersNotifiesLatestUpdatesToSlowSubscriber(t *testing.T) {
	cache := New(logger, nil)

	sub, err := NewSubscriber(Selectors{&common.Selector{Type: "unix", Value: "uid:1111"}})
	assert.Nil(t, err)

	cache.Subscribe(sub)

	var wg sync.WaitGroup

	wg.Add(1)
	var i int

	go func() {
		defer wg.Done()
		for i = 0; i < 1000; i++ {
			e := &Entry{
				RegistrationEntry: &common.RegistrationEntry{
					Selectors: Selectors{
						&common.Selector{Type: "unix", Value: "uid:1111"},
					},
					ParentId: "spiffe:parent2",
					SpiffeId: fmt.Sprintf("spiffe:test2_%d", i),
					EntryId:  "00000000-0000-0000-0000-000000000002",
				},
				SVID:       &x509.Certificate{},
				PrivateKey: privateKey,
			}
			cache.SetEntry(e)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		var lastI int = -1
		for i != 1000 || len(sub.Updates()) != 0 {
			wu := <-sub.Updates()
			if len(wu.Entries) == 1 {
				parts := strings.Split(wu.Entries[0].RegistrationEntry.SpiffeId, "_")
				currentI, _ := strconv.Atoi(parts[1])
				// SpiffeId suffixes should be always increasing.
				assert.True(t, lastI < currentI)
				lastI = currentI

				fmt.Printf("%v\n", lastI)
				time.Sleep(2 * time.Millisecond)
			}
		}
	}()

	wg.Wait()
}
