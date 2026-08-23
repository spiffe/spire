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

func sortIdentities(identities []X509Identity) {
	sort.Slice(identities, func(a, b int) bool {
		return identities[a].Entry.EntryId < identities[b].Entry.EntryId
	})
}
