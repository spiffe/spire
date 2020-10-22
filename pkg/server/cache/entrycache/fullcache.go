package entrycache

import (
	"context"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/proto/spire/types"
)

var (
	seenSetPool = sync.Pool{
		New: func() interface{} {
			return make(seenSet)
		},
	}

	stringSetPool = sync.Pool{
		New: func() interface{} {
			return make(stringSet)
		},
	}
)

var _ Cache = (*FullEntryCache)(nil)

// Cache contains a snapshot of all registration entries and Agent selectors from the data source
// at a particular moment in time.
type Cache interface {
	GetAuthorizedEntries(agentID spiffeid.ID) []*types.Entry
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
//   for it.Next() {
//       entry := it.Entry()
//       // process entry
//   }
//
//   if it.Err() {
//       // handle error
//   }
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
//   for it.Next() {
//       agent := it.Agent()
//       // process agent
//   }
//
//   if it.Err() {
//       // handle error
//   }
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
	aliases map[spiffeID][]aliasEntry
	entries map[spiffeID][]*types.Entry
}

type selectorSet map[Selector]struct{}
type seenSet map[spiffeID]struct{}
type stringSet map[string]struct{}

type spiffeID struct {
	// TrustDomain is the trust domain of the SPIFFE ID.
	TrustDomain string
	// Path is the path of the SPIFFE ID.
	Path string
}

type aliasEntry struct {
	id    spiffeID
	entry *types.Entry
}

// Build queries the data source for all registration entries and Agent selectors and builds an in-memory
// representation of the data that can be used for efficient lookups.
func Build(ctx context.Context, entryIter EntryIterator, agentIter AgentIterator) (*FullEntryCache, error) {
	type aliasInfo struct {
		aliasEntry
		selectors selectorSet
	}
	bysel := make(map[Selector][]aliasInfo)

	entries := make(map[spiffeID][]*types.Entry)
	for entryIter.Next(ctx) {
		entry := entryIter.Entry()
		parentID := spiffeIDFromProto(entry.ParentId)
		if parentID.Path == "/spire/server" {
			alias := aliasInfo{
				aliasEntry: aliasEntry{
					id:    spiffeIDFromProto(entry.SpiffeId),
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

	aliases := make(map[spiffeID][]aliasEntry)
	for agentIter.Next(ctx) {
		agent := agentIter.Agent()
		agentID := spiffeIDFromID(agent.ID)
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

// GetAuthorizedEntries gets all authorized registration entries for a given Agent SPIFFE ID.
func (c *FullEntryCache) GetAuthorizedEntries(agentID spiffeid.ID) []*types.Entry {
	seen := allocSeenSet()
	defer freeSeenSet(seen)

	return c.getAuthorizedEntries(spiffeIDFromID(agentID), seen)
}

func (c *FullEntryCache) getAuthorizedEntries(id spiffeID, seen map[spiffeID]struct{}) []*types.Entry {
	entries := c.crawl(id, seen)
	for _, descendant := range entries {
		entries = append(entries, c.getAuthorizedEntries(spiffeIDFromProto(descendant.SpiffeId), seen)...)
	}

	for _, alias := range c.aliases[id] {
		entries = append(entries, alias.entry)
		entries = append(entries, c.getAuthorizedEntries(alias.id, seen)...)
	}
	return entries
}

func (c *FullEntryCache) crawl(parentID spiffeID, seen map[spiffeID]struct{}) []*types.Entry {
	if _, ok := seen[parentID]; ok {
		return nil
	}
	seen[parentID] = struct{}{}

	// Make a copy so that the entries aren't aliasing the backing array
	entries := append([]*types.Entry(nil), c.entries[parentID]...)
	for _, entry := range entries {
		entries = append(entries, c.crawl(spiffeIDFromProto(entry.SpiffeId), seen)...)
	}
	return entries
}

func spiffeIDFromID(id spiffeid.ID) spiffeID {
	return spiffeID{
		TrustDomain: id.TrustDomain().String(),
		Path:        id.Path(),
	}
}

func spiffeIDFromProto(id *types.SPIFFEID) spiffeID {
	return spiffeID{
		TrustDomain: id.TrustDomain,
		Path:        id.Path,
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
