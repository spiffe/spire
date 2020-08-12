package entrycache

import (
	"context"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/proto/spire/types"
)

var (
	selectorSetPool = sync.Pool{
		New: func() interface{} {
			return make(selectorSet)
		},
	}

	seenSetPool = sync.Pool{
		New: func() interface{} {
			return make(seenSet)
		},
	}
)

type selectorSet map[Selector]struct{}
type seenSet map[spiffeID]struct{}

type Selector struct {
	Type  string
	Value string
}

type EntryIterator interface {
	Next(ctx context.Context) bool
	Entry() *types.Entry
	Err() error
}

type AgentIterator interface {
	Next(ctx context.Context) bool
	Agent() Agent
	Err() error
}

type Agent struct {
	ID        spiffeid.ID
	Selectors []*types.Selector
}

type spiffeID struct {
	TrustDomain string
	Path        string
}

type aliasEntry struct {
	id    spiffeID
	entry *types.Entry
}

type Cache struct {
	aliases map[spiffeID][]aliasEntry
	entries map[spiffeID][]*types.Entry
}

func Build(ctx context.Context, entryIter EntryIterator, agentIter AgentIterator) (*Cache, error) {
	type aliasInfo struct {
		aliasEntry
		selectors selectorSet
	}
	bysel := make(map[Selector]aliasInfo)

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
				bysel[selector] = alias
			}
			continue
		}
		entries[parentID] = append(entries[parentID], entry)
	}
	if err := entryIter.Err(); err != nil {
		return nil, err
	}

	aliasSeen := allocSeenSet()
	defer freeSeenSet(aliasSeen)

	aliases := make(map[spiffeID][]aliasEntry)
	for agentIter.Next(ctx) {
		agent := agentIter.Agent()
		agentID := spiffeIDFromID(agent.ID)
		agentSelectors := selectorSetFromProto(agent.Selectors)
		// track which aliases we've evaluated so far to make sure we don't
		// add one twice.
		clearSeenSet(aliasSeen)
		for s := range agentSelectors {
			alias, ok := bysel[s]
			if !ok {
				continue
			}
			if _, ok := aliasSeen[alias.id]; ok {
				continue
			}
			aliasSeen[alias.id] = struct{}{}
			if isSubset(alias.selectors, agentSelectors) {
				aliases[agentID] = append(aliases[agentID], alias.aliasEntry)
			}
		}
	}
	if err := agentIter.Err(); err != nil {
		return nil, err
	}

	return &Cache{
		aliases: aliases,
		entries: entries,
	}, nil
}

func (c *Cache) GetAuthorizedEntries(agentID spiffeid.ID) []*types.Entry {
	seen := allocSeenSet()
	defer freeSeenSet(seen)

	return c.getAuthorizedEntries(spiffeIDFromID(agentID), seen)
}

func (c *Cache) getAuthorizedEntries(id spiffeID, seen map[spiffeID]struct{}) []*types.Entry {
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

func (c *Cache) crawl(parentID spiffeID, seen map[spiffeID]struct{}) []*types.Entry {
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

func allocSelectorSet() selectorSet {
	return selectorSetPool.Get().(selectorSet)

}

func freeSelectorSet(set selectorSet) {
	clearSelectorSet(set)
	selectorSetPool.Put(set)
}

func clearSelectorSet(set selectorSet) {
	for k := range set {
		delete(set, k)
	}
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
