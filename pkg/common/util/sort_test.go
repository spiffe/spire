package util

import (
	"math/rand"
	"reflect"
	"testing"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
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
		{SpiffeId: "a", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "b", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "c", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		// entries to assert that parent ids are compared for sorting second
		{SpiffeId: "x", ParentId: "a", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "b", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "c", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		// entries to assert that x509SvidTtl is compared for sorting third
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 10, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 20, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 30, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		// entries to assert that jwtSvidTtl is compared for sorting fourth
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 10, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 20, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 30, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		// entries to assert that selector types are compared for sorting fifth
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "a", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "b", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "c", Value: "x"}}},
		// entries to assert that selector values are included in selector sorting
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "a"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "b"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "c"}}},
		// entry to assert that entries with more selectors come after entries with less
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "a", Value: "a"}, {Type: "a", Value: "b"}}},
		// entry to assert that selectors get sorted as well
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "a", Value: "c"}, {Type: "a", Value: "a"}}},
	}

	expected := []*common.RegistrationEntry{
		{SpiffeId: "a", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "b", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "c", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "a", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "b", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "c", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 10, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 20, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 30, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 10, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 20, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 30, Selectors: []*common.Selector{{Type: "x", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "a", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "b", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "c", Value: "x"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "a"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "b"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "x", Value: "c"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "a", Value: "a"}, {Type: "a", Value: "b"}}},
		{SpiffeId: "x", ParentId: "x", X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*common.Selector{{Type: "a", Value: "a"}, {Type: "a", Value: "c"}}},
	}

	var actual []*common.RegistrationEntry
	for {
		actual = shuffleRegistrationEntries(entries)
		if !reflect.DeepEqual(actual, entries) {
			break
		}
	}
	SortRegistrationEntries(actual)
	assertRegistrationEntries(t, actual, expected, "failed to sort registration entries")
}

func shuffleRegistrationEntries(rs []*common.RegistrationEntry) []*common.RegistrationEntry {
	shuffled := append([]*common.RegistrationEntry{}, rs...)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	return shuffled
}

func assertRegistrationEntries(t *testing.T, actual, expected []*common.RegistrationEntry, msg string) {
	if !spiretest.AssertProtoListEqual(t, actual, expected) {
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

func TestSortTypesEntries(t *testing.T) {
	idA := &types.SPIFFEID{TrustDomain: "a"}
	idB := &types.SPIFFEID{TrustDomain: "b"}
	idC := &types.SPIFFEID{TrustDomain: "c"}
	idX := &types.SPIFFEID{TrustDomain: "x"}

	selectorsX := []*types.Selector{{Type: "x", Value: "x"}}

	entries := []*types.Entry{
		// entries to assert that spiffe ids are compared for sorting first
		{SpiffeId: idA, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: selectorsX},
		{SpiffeId: idB, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: selectorsX},
		{SpiffeId: idC, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: selectorsX},
		// entries to assert that parent ids are compared for sorting second
		{SpiffeId: idX, ParentId: idA, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: selectorsX},
		{SpiffeId: idX, ParentId: idB, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: selectorsX},
		{SpiffeId: idX, ParentId: idC, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: selectorsX},
		// entries to assert that x509SvidTtl is compared for sorting third
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 10, JwtSvidTtl: 110, Selectors: selectorsX},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 20, JwtSvidTtl: 110, Selectors: selectorsX},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 30, JwtSvidTtl: 110, Selectors: selectorsX},
		// entries to assert that jwtSvidTtl is compared for sorting forth
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 10, Selectors: selectorsX},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 20, Selectors: selectorsX},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 30, Selectors: selectorsX},

		// entries to assert that selector types are compared for sorting fifth
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*types.Selector{{Type: "a", Value: "x"}}},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*types.Selector{{Type: "b", Value: "x"}}},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*types.Selector{{Type: "c", Value: "x"}}},
		// entries to assert that selector values are included in selector sorting
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*types.Selector{{Type: "x", Value: "a"}}},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*types.Selector{{Type: "x", Value: "b"}}},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*types.Selector{{Type: "x", Value: "c"}}},
		// entry to assert that entries with more selectors come after entries with less
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*types.Selector{{Type: "a", Value: "a"}, {Type: "a", Value: "b"}}},
		// entry to assert that selectors get sorted as well
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*types.Selector{{Type: "a", Value: "c"}, {Type: "a", Value: "a"}}},
	}

	expected := []*types.Entry{
		{SpiffeId: &types.SPIFFEID{TrustDomain: "a"}, ParentId: &types.SPIFFEID{TrustDomain: "x"}, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: selectorsX},
		{SpiffeId: &types.SPIFFEID{TrustDomain: "b"}, ParentId: &types.SPIFFEID{TrustDomain: "x"}, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: selectorsX},
		{SpiffeId: &types.SPIFFEID{TrustDomain: "c"}, ParentId: &types.SPIFFEID{TrustDomain: "x"}, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: selectorsX},
		{SpiffeId: &types.SPIFFEID{TrustDomain: "x"}, ParentId: &types.SPIFFEID{TrustDomain: "a"}, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: selectorsX},
		{SpiffeId: &types.SPIFFEID{TrustDomain: "x"}, ParentId: &types.SPIFFEID{TrustDomain: "b"}, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: selectorsX},
		{SpiffeId: &types.SPIFFEID{TrustDomain: "x"}, ParentId: &types.SPIFFEID{TrustDomain: "c"}, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: selectorsX},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 10, JwtSvidTtl: 110, Selectors: selectorsX},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 20, JwtSvidTtl: 110, Selectors: selectorsX},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 30, JwtSvidTtl: 110, Selectors: selectorsX},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 10, Selectors: selectorsX},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 20, Selectors: selectorsX},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 30, Selectors: selectorsX},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*types.Selector{{Type: "a", Value: "x"}}},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*types.Selector{{Type: "b", Value: "x"}}},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*types.Selector{{Type: "c", Value: "x"}}},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*types.Selector{{Type: "x", Value: "a"}}},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*types.Selector{{Type: "x", Value: "b"}}},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*types.Selector{{Type: "x", Value: "c"}}},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*types.Selector{{Type: "a", Value: "a"}, {Type: "a", Value: "b"}}},
		{SpiffeId: idX, ParentId: idX, X509SvidTtl: 100, JwtSvidTtl: 110, Selectors: []*types.Selector{{Type: "a", Value: "a"}, {Type: "a", Value: "c"}}},
	}

	var actual []*types.Entry
	for {
		actual = shuffleTypesEntries(entries)
		if !reflect.DeepEqual(actual, entries) {
			break
		}
	}
	SortTypesEntries(actual)
	assertTypesEntries(t, actual, expected, "failed to sort registration entries")
}

func shuffleTypesEntries(rs []*types.Entry) []*types.Entry {
	shuffled := append([]*types.Entry{}, rs...)
	rand.Shuffle(len(rs), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	return shuffled
}

func assertTypesEntries(t *testing.T, actual, expected []*types.Entry, msg string) {
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
