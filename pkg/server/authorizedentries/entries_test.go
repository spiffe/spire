package authorizedentries

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEntryRecordByEntryID(t *testing.T) {
	assertLess := func(lesser, greater entryRecord) {
		t.Helper()
		assert.True(t, entryRecordByEntryID(lesser, greater), "expected E%sP%s<E%sP%s", lesser.EntryID, lesser.ParentID, greater.EntryID, greater.ParentID)
		assert.False(t, entryRecordByEntryID(greater, lesser), "expected E%sP%s>E%sP%s", greater.EntryID, greater.ParentID, lesser.EntryID, lesser.ParentID)
	}

	records := []entryRecord{
		entryRecord{EntryID: "1"},
		entryRecord{EntryID: "1", ParentID: "1"},
		entryRecord{EntryID: "1", ParentID: "2"},
		entryRecord{EntryID: "2"},
		entryRecord{EntryID: "2", ParentID: "1"},
		entryRecord{EntryID: "2", ParentID: "2"},
	}

	lesser := entryRecord{}
	for _, greater := range records {
		assertLess(lesser, greater)
		lesser = greater
	}
}

func TestEntryRecordByParentID(t *testing.T) {
	assertLess := func(lesser, greater entryRecord) {
		t.Helper()
		assert.True(t, entryRecordByParentID(lesser, greater), "expected P%sE%s<P%sE%s", lesser.ParentID, lesser.EntryID, greater.ParentID, greater.EntryID)
		assert.False(t, entryRecordByParentID(greater, lesser), "expected P%sE%s>P%sE%s", greater.ParentID, greater.EntryID, lesser.ParentID, lesser.EntryID)
	}

	records := []entryRecord{
		entryRecord{ParentID: "1"},
		entryRecord{ParentID: "1", EntryID: "1"},
		entryRecord{ParentID: "1", EntryID: "2"},
		entryRecord{ParentID: "2"},
		entryRecord{ParentID: "2", EntryID: "1"},
		entryRecord{ParentID: "2", EntryID: "2"},
	}

	lesser := entryRecord{}
	for _, greater := range records {
		assertLess(lesser, greater)
		lesser = greater
	}
}
