package entrycache

import (
	"context"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api"
)

var (
	seenSetPool = sync.Pool{
		New: func() any {
			return make(seenSet)
		},
	}

	stringSetPool = sync.Pool{
		New: func() any {
			return make(stringSet)
		},
	}
)

var _ Cache = (*FullEntryCache)(nil)

// Cache contains a snapshot of all registration entries and Agent selectors from the data source
// at a particular moment in time.
type Cache interface {
	LookupAuthorizedEntries(agentID spiffeid.ID, entries map[string]struct{}) map[string]api.ReadOnlyEntry
	GetAuthorizedEntries(agentID spiffeid.ID) []api.ReadOnlyEntry
}

// Selector is a key-value attribute of a node or workload.
type Selector struct {
	// Type is the type of the selector.
	Type string
	// Value is the value of the selector.
	Value string
}

// EntryIterator is used to iterate through registration entries from a data source.
// The usage pattern of the iterator is as follows:
//
//	for it.Next() {
//	    entry := it.Entry()
//	    // process entry
//	}
//
//	if it.Err() {
//	    // handle error
//	}
type EntryIterator interface {
	// Next returns true if there are any remaining registration entries in the data source and returns false otherwise.
	Next(ctx context.Context) bool
	// Entry returns the next entry from the data source.
	Entry() *types.Entry
	// Err returns an error encountered when attempting to process entries from the data source.
	Err() error
}

// AgentIterator is used to iterate through Agent selectors from a data source.
// The usage pattern of the iterator is as follows:
//
//	for it.Next() {
//	    agent := it.Agent()
//	    // process agent
//	}
//
//	if it.Err() {
//	    // handle error
//	}
type AgentIterator interface {
	// Next returns true if there are any remaining agents in the data source and returns false otherwise.
	Next(ctx context.Context) bool
	// Agent returns the next agent from the data source.
	Agent() Agent
	// Err returns an error encountered when attempting to process agents from the data source.
	Err() error
}

// Agent represents the association of selectors to an agent SPIFFE ID.
type Agent struct {
	// ID is the Agent's SPIFFE ID.
	ID spiffeid.ID
	// Selectors is the Agent's selectors.
	Selectors []*types.Selector
}

type FullEntryCache struct {
	aliases map[string][]aliasEntry
	entries map[string][]*types.Entry
}

type selectorSet map[Selector]struct{}
type seenSet map[string]struct{}
type stringSet map[string]struct{}

type aliasEntry struct {
	id    string
	entry *types.Entry
}

// Build queries the data source for all registration entries and Agent selectors and builds an in-memory
// representation of the data that can be used for efficient lookups.
func Build(ctx context.Context, trustDomain string, entryIter EntryIterator, agentIter AgentIterator) (*FullEntryCache, error) {
	type aliasInfo struct {
		aliasEntry
		selectors selectorSet
	}
	bysel := make(map[Selector][]aliasInfo)

	entries := make(map[string][]*types.Entry)
	for entryIter.Next(ctx) {
		entry := entryIter.Entry()
		if entry.ParentId.TrustDomain != trustDomain {
			continue
		}
		if entry.SpiffeId.TrustDomain != trustDomain {
			continue
		}

		parentID := entry.ParentId.Path
		if entry.ParentId.Path == "/spire/server" {
			alias := aliasInfo{
				aliasEntry: aliasEntry{
					id:    entry.SpiffeId.Path,
					entry: entry,
				},
				selectors: selectorSetFromProto(entry.Selectors),
			}
			for selector := range alias.selectors {
				bysel[selector] = append(bysel[selector], alias)
			}
			continue
		}
		entries[parentID] = append(entries[parentID], entry)
	}
	if err := entryIter.Err(); err != nil {
		return nil, err
	}

	aliasSeen := allocStringSet()
	defer freeStringSet(aliasSeen)

	aliases := make(map[string][]aliasEntry)
	for agentIter.Next(ctx) {
		agent := agentIter.Agent()

		if agent.ID.TrustDomain().String() != trustDomain {
			continue
		}

		agentID := agent.ID.Path()
		agentSelectors := selectorSetFromProto(agent.Selectors)
		// track which aliases we've evaluated so far to make sure we don't
		// add one twice.
		clearStringSet(aliasSeen)
		for s := range agentSelectors {
			for _, alias := range bysel[s] {
				if _, ok := aliasSeen[alias.entry.Id]; ok {
					continue
				}
				aliasSeen[alias.entry.Id] = struct{}{}
				if isSubset(alias.selectors, agentSelectors) {
					aliases[agentID] = append(aliases[agentID], alias.aliasEntry)
				}
			}
		}
	}
	if err := agentIter.Err(); err != nil {
		return nil, err
	}

	return &FullEntryCache{
		aliases: aliases,
		entries: entries,
	}, nil
}

func (c *FullEntryCache) LookupAuthorizedEntries(agentID spiffeid.ID, requestedEntries map[string]struct{}) map[string]api.ReadOnlyEntry {
	seen := allocSeenSet()
	defer freeSeenSet(seen)

	foundEntries := make(map[string]api.ReadOnlyEntry)
	c.crawl(agentID.Path(), seen, func(entry *types.Entry) {
		if _, ok := requestedEntries[entry.Id]; ok {
			foundEntries[entry.Id] = api.NewReadOnlyEntry(entry)
		}
	})

	return foundEntries
}

// GetAuthorizedEntries gets all authorized registration entries for a given Agent SPIFFE ID.
func (c *FullEntryCache) GetAuthorizedEntries(agentID spiffeid.ID) []api.ReadOnlyEntry {
	seen := allocSeenSet()
	defer freeSeenSet(seen)

	foundEntries := []api.ReadOnlyEntry{}
	c.crawl(agentID.Path(), seen, func(entry *types.Entry) {
		foundEntries = append(foundEntries, api.NewReadOnlyEntry(entry))
	})

	return foundEntries
}

func (c *FullEntryCache) crawl(parentID string, seen map[string]struct{}, visit func(*types.Entry)) {
	if _, ok := seen[parentID]; ok {
		return
	}
	seen[parentID] = struct{}{}

	for _, entry := range c.entries[parentID] {
		visit(entry)
		c.crawl(entry.SpiffeId.Path, seen, visit)
	}

	for _, alias := range c.aliases[parentID] {
		c.crawl(alias.id, seen, visit)
	}
}

func selectorSetFromProto(selectors []*types.Selector) selectorSet {
	set := make(selectorSet, len(selectors))
	for _, selector := range selectors {
		set[Selector{Type: selector.Type, Value: selector.Value}] = struct{}{}
	}
	return set
}

func allocSeenSet() seenSet {
	return seenSetPool.Get().(seenSet)
}

func freeSeenSet(set seenSet) {
	clearSeenSet(set)
	seenSetPool.Put(set)
}

func clearSeenSet(set seenSet) {
	for k := range set {
		delete(set, k)
	}
}

func allocStringSet() stringSet {
	return stringSetPool.Get().(stringSet)
}

func freeStringSet(set stringSet) {
	clearStringSet(set)
	stringSetPool.Put(set)
}

func clearStringSet(set stringSet) {
	for k := range set {
		delete(set, k)
	}
}

func isSubset(sub, whole selectorSet) bool {
	if len(sub) > len(whole) {
		return false
	}
	for s := range sub {
		if _, ok := whole[s]; !ok {
			return false
		}
	}
	return true
}
