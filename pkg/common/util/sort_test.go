package util

import (
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/spiffe/spire/proto/spire/common"
)

func TestDedupRegistrationEntries(t *testing.T) {
	entries := []*common.RegistrationEntry{
		{SpiffeId: "c"},
		{SpiffeId: "a"},
		{SpiffeId: "b"},
		{SpiffeId: "c"},
		{SpiffeId: "c"},
		{SpiffeId: "c"},
		{SpiffeId: "b"},
	}

	expected := []*common.RegistrationEntry{
		{SpiffeId: "a"},
		{SpiffeId: "b"},
		{SpiffeId: "c"},
	}

	actual := DedupRegistrationEntries(entries)
	assertRegistrationEntries(t, actual, expected, "failed to sort registration entries")
}

func TestSortRegistrationEntries(t *testing.T) {
	entries := []*common.RegistrationEntry{
		// entries to assert that spiffe ids are compared for sorting first
		{SpiffeId: "a", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "b", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "c", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		// entries to assert that parent ids are compared for sorting second
		{SpiffeId: "x", ParentId: "a", Ttl: 90, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "b", Ttl: 90, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "c", Ttl: 90, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		// entries to assert that ttl is compared for sorting third
		{SpiffeId: "x", ParentId: "x", Ttl: 10, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", Ttl: 20, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", Ttl: 30, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		// entries to assert that selector types are compared for sorting fourth
		{SpiffeId: "x", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "a", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "b", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "c", Value: "x"}}},
		// entries to assert that selector values are included in selector sorting
		{SpiffeId: "x", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "x", Value: "a"}}},
		{SpiffeId: "x", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "x", Value: "b"}}},
		{SpiffeId: "x", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "x", Value: "c"}}},
		// entry to assert that entries with more selectors come after entries with less
		{SpiffeId: "x", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "a", Value: "a"}, {Type: "a", Value: "b"}}},
		// entry to assert that selectors get sorted as well
		{SpiffeId: "x", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "a", Value: "c"}, {Type: "a", Value: "a"}}},
	}

	expected := []*common.RegistrationEntry{
		{SpiffeId: "a", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "b", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "c", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "a", Ttl: 90, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "b", Ttl: 90, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "c", Ttl: 90, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", Ttl: 10, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", Ttl: 20, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", Ttl: 30, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "a", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "b", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "c", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "x", Value: "a"}}},
		{SpiffeId: "x", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "x", Value: "b"}}},
		{SpiffeId: "x", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "x", Value: "c"}}},
		{SpiffeId: "x", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "a", Value: "a"}, {Type: "a", Value: "b"}}},
		{SpiffeId: "x", ParentId: "x", Ttl: 90, Selectors: []*common.Selector{{Type: "a", Value: "a"}, {Type: "a", Value: "c"}}},
	}

	rnd := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))

	var actual []*common.RegistrationEntry
	for {
		actual = shuffleRegistrationEntries(rnd, entries)
		if !reflect.DeepEqual(actual, entries) {
			break
		}
	}
	SortRegistrationEntries(actual)
	assertRegistrationEntries(t, actual, expected, "failed to sort registration entries")
}

func shuffleRegistrationEntries(rnd *rand.Rand, rs []*common.RegistrationEntry) []*common.RegistrationEntry {
	shuffled := make([]*common.RegistrationEntry, len(rs))
	for i, v := range rnd.Perm(len(rs)) {
		shuffled[v] = rs[i]
	}
	return shuffled
}

func assertRegistrationEntries(t *testing.T, actual, expected []*common.RegistrationEntry, msg string) {
	if !reflect.DeepEqual(actual, expected) {
		t.Logf("ACTUAL:")
		for i, entry := range actual {
			t.Logf("[%d] %v", i, entry)
		}
		t.Logf("EXPECTED:")
		for i, entry := range expected {
			t.Logf("[%d] %v", i, entry)
		}
		t.Fatal(msg)
	}
}
