package cache

import (
	"sort"

	"github.com/spiffe/spire/proto/spire/common"
)

func sortEntriesByID(entries []*common.RegistrationEntry) {
	sort.Slice(entries, func(a, b int) bool {
		return entries[a].EntryId < entries[b].EntryId
	})
}
