package cache

import (
	"sort"

	"github.com/spiffe/spire/proto/spire/common"
)

type Selectors []*common.Selector

func sortEntriesByID(entries []*common.RegistrationEntry) {
	sort.Slice(entries, func(a, b int) bool {
		return entries[a].EntryId < entries[b].EntryId
	})
}

// identity is implemented by the per-SVID-type identities held in a workload
// update.
type identity interface {
	entryID() string
}

func sortIdentities[T identity](identities []T) {
	sort.Slice(identities, func(a, b int) bool {
		return identities[a].entryID() < identities[b].entryID()
	})
}
