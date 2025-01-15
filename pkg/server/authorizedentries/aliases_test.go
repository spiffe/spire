package authorizedentries

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAliasRecordSize(t *testing.T) {
	// The motivation for this test is to bring awareness and visibility into
	// how much size the record occupies. We want to minimize the size to
	// increase cache locality in the btree.
	require.Equal(t, uintptr(72), unsafe.Sizeof(aliasRecord{}))
}

func TestAliasRecordByEntryID(t *testing.T) {
	assertLess := func(lesser, greater aliasRecord) {
		t.Helper()
		assert.Truef(t, aliasRecordByEntryID(lesser, greater), "expected E%sP%s<E%sP%s", lesser.EntryID, lesser.Selector, greater.EntryID, greater.Selector)
		assert.Falsef(t, aliasRecordByEntryID(greater, lesser), "expected E%sP%s>E%sP%s", greater.EntryID, greater.Selector, lesser.EntryID, lesser.Selector)
	}

	records := []aliasRecord{
		{EntryID: "1"},
		{EntryID: "1", Selector: Selector{Type: "1", Value: "1"}},
		{EntryID: "1", Selector: Selector{Type: "1", Value: "2"}},
		{EntryID: "1", Selector: Selector{Type: "2", Value: "1"}},
		{EntryID: "1", Selector: Selector{Type: "2", Value: "2"}},
		{EntryID: "2"},
		{EntryID: "2", Selector: Selector{Type: "1", Value: "1"}},
		{EntryID: "2", Selector: Selector{Type: "1", Value: "2"}},
		{EntryID: "2", Selector: Selector{Type: "2", Value: "1"}},
		{EntryID: "2", Selector: Selector{Type: "2", Value: "2"}},
	}

	lesser := aliasRecord{}
	for _, greater := range records {
		assertLess(lesser, greater)
		lesser = greater
	}
}

func TestAliasRecordBySelector(t *testing.T) {
	assertLess := func(lesser, greater aliasRecord) {
		t.Helper()
		assert.True(t, aliasRecordBySelector(lesser, greater), "expected P%sE%s<P%sE%s", lesser.Selector, lesser.EntryID, greater.Selector, greater.EntryID)
		assert.False(t, aliasRecordBySelector(greater, lesser), "expected P%sE%s>P%sE%s", greater.Selector, greater.EntryID, lesser.Selector, lesser.EntryID)
	}

	records := []aliasRecord{
		{Selector: Selector{Type: "1", Value: "1"}},
		{Selector: Selector{Type: "1", Value: "1"}, EntryID: "1"},
		{Selector: Selector{Type: "1", Value: "1"}, EntryID: "2"},
		{Selector: Selector{Type: "1", Value: "2"}, EntryID: "1"},
		{Selector: Selector{Type: "1", Value: "2"}, EntryID: "2"},
		{Selector: Selector{Type: "2", Value: "1"}},
		{Selector: Selector{Type: "2", Value: "1"}, EntryID: "1"},
		{Selector: Selector{Type: "2", Value: "1"}, EntryID: "2"},
		{Selector: Selector{Type: "2", Value: "2"}},
		{Selector: Selector{Type: "2", Value: "2"}, EntryID: "1"},
		{Selector: Selector{Type: "2", Value: "2"}, EntryID: "2"},
	}
	lesser := aliasRecord{}
	for _, greater := range records {
		assertLess(lesser, greater)
		lesser = greater
	}
}
