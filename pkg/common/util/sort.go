package util

import (
	"sort"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/spiffe/spire/proto/spire/common"
)

func DedupRegistrationEntries(entries []*common.RegistrationEntry) []*common.RegistrationEntry {
	if len(entries) == 0 {
		return entries
	}

	entries = cloneRegistrationEntries(entries)
	SortRegistrationEntries(entries)

	deduped := make([]*common.RegistrationEntry, 0, len(entries))
	deduped = append(deduped, entries[0])
	for _, entry := range entries[1:] {
		if compareRegistrationEntries(deduped[len(deduped)-1], entry) != 0 {
			deduped = append(deduped, entry)
		}
	}

	return deduped
}

func SortRegistrationEntries(entries []*common.RegistrationEntry) {
	// first, sort the selectors for each entry, since the registration
	// entry comparison relies on them being sorted
	for _, entry := range entries {
		SortSelectors(entry.Selectors)
	}

	// second, sort the registration entries
	sort.Slice(entries, func(i, j int) bool {
		return compareRegistrationEntries(entries[i], entries[j]) < 0
	})
}

func SortSelectors(selectors []*common.Selector) {
	sort.Slice(selectors, func(i, j int) bool {
		return compareSelector(selectors[i], selectors[j]) < 0
	})
}

func compareRegistrationEntries(a, b *common.RegistrationEntry) int {
	c := strings.Compare(a.SpiffeId, b.SpiffeId)
	if c != 0 {
		return c
	}

	c = strings.Compare(a.ParentId, b.ParentId)
	if c != 0 {
		return c
	}

	switch {
	case a.Ttl < b.Ttl:
		return -1
	case a.Ttl > b.Ttl:
		return 1
	}

	return compareSelectors(a.Selectors, b.Selectors)
}

func compareSelectors(a, b []*common.Selector) int {
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	for i := range a {
		c := compareSelector(a[i], b[i])
		if c != 0 {
			return c
		}
	}
	return 0
}

func compareSelector(a, b *common.Selector) int {
	c := strings.Compare(a.Type, b.Type)
	if c != 0 {
		return c
	}
	return strings.Compare(a.Value, b.Value)
}

func cloneRegistrationEntries(entries []*common.RegistrationEntry) []*common.RegistrationEntry {
	cloned := make([]*common.RegistrationEntry, 0, len(entries))
	for _, entry := range entries {
		cloned = append(cloned, cloneRegistrationEntry(entry))
	}
	return cloned
}

func cloneRegistrationEntry(entry *common.RegistrationEntry) *common.RegistrationEntry {
	return proto.Clone(entry).(*common.RegistrationEntry)
}
