// Package hintsfilter deduplicates registration entries (and the identities
// derived from them) so that callers of the agent's local APIs see at most
// one entry per hint. Used by both the Workload API and the SPIFFE Broker
// API so that hint semantics are consistent across them.
package hintsfilter

import (
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
)

// FilterRegistrations returns entries with duplicate hints removed,
// preferring the older entry (by CreatedAt) with EntryId as the
// deterministic tie-breaker.
func FilterRegistrations(entries []*common.RegistrationEntry, log logrus.FieldLogger) []*common.RegistrationEntry {
	entriesToRemove := getEntriesToRemove(entries, log)

	var filteredEntries []*common.RegistrationEntry
	for _, entry := range entries {
		if _, ok := entriesToRemove[entry.EntryId]; !ok {
			filteredEntries = append(filteredEntries, entry)
		}
	}
	return filteredEntries
}

// FilterIdentities returns identities whose underlying registration entries
// survive hint deduplication. Same tie-breaking rules as FilterRegistrations.
func FilterIdentities(identities []cache.Identity, log logrus.FieldLogger) []cache.Identity {
	entries := make([]*common.RegistrationEntry, 0, len(identities))
	for _, identity := range identities {
		entries = append(entries, identity.Entry)
	}
	entriesToRemove := getEntriesToRemove(entries, log)

	var filteredIdentities []cache.Identity
	for _, identity := range identities {
		if _, ok := entriesToRemove[identity.Entry.EntryId]; !ok {
			filteredIdentities = append(filteredIdentities, identity)
		}
	}
	return filteredIdentities
}

func getEntriesToRemove(entries []*common.RegistrationEntry, log logrus.FieldLogger) map[string]struct{} {
	entriesToRemove := make(map[string]struct{})
	hintsMap := make(map[string]*common.RegistrationEntry)

	for _, entry := range entries {
		if entry.Hint == "" {
			continue
		}
		if entryWithNonUniqueHint, ok := hintsMap[entry.Hint]; ok {
			entryToMaintain, entryToRemove := hintTieBreaking(entry, entryWithNonUniqueHint)

			hintsMap[entry.Hint] = entryToMaintain
			entriesToRemove[entryToRemove.EntryId] = struct{}{}

			log.WithFields(logrus.Fields{
				telemetry.Hint:           entryToRemove.Hint,
				telemetry.RegistrationID: entryToRemove.EntryId,
			}).Warn("Ignoring entry with duplicate hint")
		} else {
			hintsMap[entry.Hint] = entry
		}
	}

	return entriesToRemove
}

func hintTieBreaking(entryA, entryB *common.RegistrationEntry) (maintain, remove *common.RegistrationEntry) {
	switch {
	case entryA.CreatedAt < entryB.CreatedAt:
		maintain = entryA
		remove = entryB
	case entryA.CreatedAt > entryB.CreatedAt:
		maintain = entryB
		remove = entryA
	default:
		if entryA.EntryId < entryB.EntryId {
			maintain = entryA
			remove = entryB
		} else {
			maintain = entryB
			remove = entryA
		}
	}
	return
}
