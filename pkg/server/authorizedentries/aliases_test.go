package authorizedentries

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAliasRecordByEntryID(t *testing.T) {
	assertLess := func(lesser, greater aliasRecord) {
		t.Helper()
		assert.True(t, aliasRecordByEntryID(lesser, greater), "expected E%sP%s<E%sP%s", lesser.EntryID, lesser.Selector, greater.EntryID, greater.Selector)
		assert.False(t, aliasRecordByEntryID(greater, lesser), "expected E%sP%s>E%sP%s", greater.EntryID, greater.Selector, lesser.EntryID, lesser.Selector)
	}

	records := []aliasRecord{
		aliasRecord{EntryID: "1"},
		aliasRecord{EntryID: "1", Selector: Selector{Type: "1", Value: "1"}},
		aliasRecord{EntryID: "1", Selector: Selector{Type: "1", Value: "2"}},
		aliasRecord{EntryID: "1", Selector: Selector{Type: "2", Value: "1"}},
		aliasRecord{EntryID: "1", Selector: Selector{Type: "2", Value: "2"}},
		aliasRecord{EntryID: "2"},
		aliasRecord{EntryID: "2", Selector: Selector{Type: "1", Value: "1"}},
		aliasRecord{EntryID: "2", Selector: Selector{Type: "1", Value: "2"}},
		aliasRecord{EntryID: "2", Selector: Selector{Type: "2", Value: "1"}},
		aliasRecord{EntryID: "2", Selector: Selector{Type: "2", Value: "2"}},
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
		aliasRecord{Selector: Selector{Type: "1", Value: "1"}},
		aliasRecord{Selector: Selector{Type: "1", Value: "1"}, EntryID: "1"},
		aliasRecord{Selector: Selector{Type: "1", Value: "1"}, EntryID: "2"},
		aliasRecord{Selector: Selector{Type: "1", Value: "2"}, EntryID: "1"},
		aliasRecord{Selector: Selector{Type: "1", Value: "2"}, EntryID: "2"},
		aliasRecord{Selector: Selector{Type: "2", Value: "1"}},
		aliasRecord{Selector: Selector{Type: "2", Value: "1"}, EntryID: "1"},
		aliasRecord{Selector: Selector{Type: "2", Value: "1"}, EntryID: "2"},
		aliasRecord{Selector: Selector{Type: "2", Value: "2"}},
		aliasRecord{Selector: Selector{Type: "2", Value: "2"}, EntryID: "1"},
		aliasRecord{Selector: Selector{Type: "2", Value: "2"}, EntryID: "2"},
	}
	lesser := aliasRecord{}
	for _, greater := range records {
		assertLess(lesser, greater)
		lesser = greater
	}
}
