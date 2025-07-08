package authorizedentries

import (
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api"
)

type entryRecord struct {
	EntryID  string
	ParentID string
	SPIFFEID string

	// Pointer to the entry. For cloning only after the end of the crawl.
	EntryCloneOnly *types.Entry
}

func entryRecordByEntryID(a, b entryRecord) bool {
	return a.EntryID < b.EntryID
}

func entryRecordByParentID(a, b entryRecord) bool {
	switch {
	case a.ParentID < b.ParentID:
		return true
	case a.ParentID > b.ParentID:
		return false
	default:
		return a.EntryID < b.EntryID
	}
}

func cloneEntriesFromRecords(entryRecords []entryRecord) []api.ReadOnlyEntry {
	if len(entryRecords) == 0 {
		return nil
	}
	cloned := make([]api.ReadOnlyEntry, 0, len(entryRecords))
	for _, entryRecord := range entryRecords {
		cloned = append(cloned, api.NewReadOnlyEntry(entryRecord.EntryCloneOnly))
	}
	return cloned
}
