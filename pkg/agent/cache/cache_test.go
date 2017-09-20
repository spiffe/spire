package cache

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	privateKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cache         = NewCache()
)

func TestCacheImpl_Valid(t *testing.T) {
	tests := []struct {
		name string
		ce   CacheEntry
	}{
		{name: "test_single_selector",
			ce: CacheEntry{
				RegistrationEntry: &common.RegistrationEntry{
					Selectors: selectors{&common.Selector{Type: "testtype", Value: "testValue"}},
					ParentId:  "spiffe:parent",
					SpiffeId:  "spiffe:test"},
				SVID:       &node.Svid{SvidCert: []byte("testcertbytes")},
				PrivateKey: privateKey,
			}},

		{name: "test_multiple_selectors_sort_same_type",
			ce: CacheEntry{
				RegistrationEntry: &common.RegistrationEntry{
					Selectors: selectors{&common.Selector{Type: "testtype3", Value: "testValue1"},
						&common.Selector{Type: "testtype1", Value: "testValue2"},
						&common.Selector{Type: "testtype1", Value: "testValue3"}},
					ParentId: "spiffe:parent",
					SpiffeId: "spiffe:test"},
				SVID:       &node.Svid{SvidCert: []byte("testcertbytes")},
				PrivateKey: privateKey,
			}}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cache.SetEntry(test.ce)
			actual := cache.Entry(test.ce.RegistrationEntry.Selectors)
			assert.Contains(t, actual, test.ce)

		})
	}
}

func TestCacheImpl_Invalid(t *testing.T) {
	tests := []struct {
		name string
		ce   CacheEntry
	}{
		{name: "test_single_selector",
			ce: CacheEntry{
				RegistrationEntry: &common.RegistrationEntry{
					Selectors: selectors{&common.Selector{Type: "testtype", Value: "testValue"}},
					ParentId:  "spiffe:parent",
					SpiffeId:  "spiffe:test"},
				SVID:       &node.Svid{SvidCert: []byte("testcertbytes")},
				PrivateKey: privateKey,
			}},

		{name: "test_multiple_selectors_sort_different_types",
			ce: CacheEntry{
				RegistrationEntry: &common.RegistrationEntry{
					Selectors: selectors{&common.Selector{Type: "testtype3", Value: "testValue1"},
						&common.Selector{Type: "testtype2", Value: "testValue2"},
						&common.Selector{Type: "testtype1", Value: "testValue3"}},
					ParentId: "spiffe:parent",
					SpiffeId: "spiffe:test"},
				SVID:       &node.Svid{SvidCert: []byte("testcertbytes")},
				PrivateKey: privateKey,
			}}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cache.SetEntry(test.ce)
			actual := cache.Entry(selectors{&common.Selector{Type: "invalid", Value: "testValue1"}})
			assert.Empty(t, actual)
		})
	}
}

func TestCacheImpl_DeleteEntry(t *testing.T) {
	tests := []struct {
		name string
		ce   CacheEntry
	}{
		{name: "test_single_selector",
			ce: CacheEntry{
				RegistrationEntry: &common.RegistrationEntry{
					Selectors: selectors{&common.Selector{Type: "testtype", Value: "testValue"}},
					ParentId:  "spiffe:parent",
					SpiffeId:  "spiffe:test"},
				SVID:       &node.Svid{SvidCert: []byte("testcertbytes")},
				PrivateKey: privateKey,
			}},

		{name: "test_multiple_selectors",
			ce: CacheEntry{
				RegistrationEntry: &common.RegistrationEntry{
					Selectors: selectors{&common.Selector{Type: "testtype3", Value: "testValue1"},
						&common.Selector{Type: "testtype2", Value: "testValue2"},
						&common.Selector{Type: "testtype1", Value: "testValue3"}},
					ParentId: "spiffe:parent",
					SpiffeId: "spiffe:test"},
				SVID:       &node.Svid{SvidCert: []byte("testcertbytes")},
				PrivateKey: privateKey,
			}}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cache.SetEntry(test.ce)
			deleted := cache.DeleteEntry(test.ce.RegistrationEntry.Selectors)
			assert.True(t, deleted)
			entry := cache.Entry(test.ce.RegistrationEntry.Selectors)
			assert.Empty(t, entry)
			deleted = cache.DeleteEntry(test.ce.RegistrationEntry.Selectors)
			assert.False(t, deleted)

		})
	}
}
