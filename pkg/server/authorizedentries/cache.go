package authorizedentries

import (
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/google/btree"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/server/api"
)

const (
	// We can tweak these degrees to try and get optimal L1 cache use, but
	// it's probably not worth it unless we have benchmarks showing that it
	// is a problem at scale in production. Initial benchmarking by myself
	// at similar scale to some of our bigger, existing deployments didn't
	// seem to yield much difference. As such, these values are probably an
	// ok jumping off point.
	agentRecordDegree = 32
	aliasRecordDegree = 32
)

type Selector struct {
	Type  string
	Value string
}

func (s Selector) String() string {
	return s.Type + ":" + s.Value
}

type EntryList struct {
	mtx     sync.RWMutex
	entries map[string]entryRecord
}

func (e *EntryList) DeleteEntry(entryID string) {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	delete(e.entries, entryID)
}

type Cache struct {
	mu  sync.RWMutex
	clk clock.Clock

	agentsByID        map[string]agentRecord
	agentsByExpiresAt *btree.BTreeG[agentRecord]

	aliasesByEntryID  *btree.BTreeG[aliasRecord]
	aliasesBySelector *btree.BTreeG[aliasRecord]

	entriesByEntryID  map[string]*types.Entry
	entriesByParentID map[string]map[string]*types.Entry
}

func NewCache(clk clock.Clock) *Cache {
	agentFreeList := btree.NewFreeListG[agentRecord](128)
	aliasFreeList := btree.NewFreeListG[aliasRecord](128)
	return &Cache{
		clk:               clk,
		agentsByID:        make(map[string]agentRecord),
		agentsByExpiresAt: btree.NewWithFreeListG(agentRecordDegree, agentRecordByExpiresAt, agentFreeList),
		aliasesByEntryID:  btree.NewWithFreeListG(aliasRecordDegree, aliasRecordByEntryID, aliasFreeList),
		aliasesBySelector: btree.NewWithFreeListG(aliasRecordDegree, aliasRecordBySelector, aliasFreeList),
		entriesByEntryID:  make(map[string]*types.Entry),
		entriesByParentID: make(map[string]map[string]*types.Entry),
	}
}

func (c *Cache) LookupAuthorizedEntries(agentID spiffeid.ID, requestedEntries map[string]struct{}) map[string]api.ReadOnlyEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Load up the agent selectors. If the agent info does not exist, it is
	// likely that the cache is still catching up to a recent attestation.
	// Since the calling agent has already been authorized and authenticated,
	// it is safe to continue with the authorized entry crawl to obtain entries
	// that are directly parented against the agent. Any entries that would be
	// obtained via node aliasing will not be returned until the cache is
	// updated with the node selectors for the agent.
	agent, _ := c.agentsByID[agentID.String()]

	foundEntries := make(map[string]api.ReadOnlyEntry)

	parentSeen := allocStringSet()
	defer freeStringSet(parentSeen)

	c.addDescendants(foundEntries, agentID.Path(), requestedEntries, parentSeen)

	agentAliases := c.getAgentAliases(agent.Selectors)
	for _, alias := range agentAliases {
		c.addDescendants(foundEntries, alias.AliasID, requestedEntries, parentSeen)
	}

	return foundEntries
}

func (c *Cache) GetAuthorizedEntries(agentID spiffeid.ID) []api.ReadOnlyEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Load up the agent selectors. If the agent info does not exist, it is
	// likely that the cache is still catching up to a recent attestation.
	// Since the calling agent has already been authorized and authenticated,
	// it is safe to continue with the authorized entry crawl to obtain entries
	// that are directly parented against the agent. Any entries that would be
	// obtained via node aliasing will not be returned until the cache is
	// updated with the node selectors for the agent.
	agent, _ := c.agentsByID[agentID.String()]

	parentSeen := allocStringSet()
	defer freeStringSet(parentSeen)

	records := make([]api.ReadOnlyEntry, 0)
	records = c.appendDescendents(records, agentID.Path(), parentSeen)

	agentAliases := c.getAgentAliases(agent.Selectors)
	for _, alias := range agentAliases {
		records = c.appendDescendents(records, alias.AliasID, parentSeen)
	}

	return records
}

func (c *Cache) UpdateEntry(entry *types.Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.removeEntry(entry.Id)
	c.updateEntry(entry)
}

func (c *Cache) RemoveEntry(entryID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.removeEntry(entryID)
}

func (c *Cache) UpdateAgent(agentID string, expiresAt time.Time, selectors []*types.Selector) {
	agent := agentRecord{
		ID:        agentID,
		ExpiresAt: expiresAt.Unix(),
		Selectors: selectorSetFromProto(selectors),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Need to delete existing record from the ExpiresAt index first. Use
	// the ID index to locate the existing record.
	currentAgent, ok := c.agentsByID[agent.ID]
	if ok {
		c.agentsByExpiresAt.Delete(currentAgent)
	}
	c.agentsByExpiresAt.ReplaceOrInsert(agent)
	c.agentsByID[agent.ID] = agent
}

func (c *Cache) RemoveAgent(agentID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	agent, ok := c.agentsByID[agentID]
	if ok {
		c.agentsByExpiresAt.Delete(agent)
	}
	delete(c.agentsByID, agentID)
}

func (c *Cache) PruneExpiredAgents() int {
	now := c.clk.Now().Unix()
	pruned := 0

	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		record, ok := c.agentsByExpiresAt.Min()
		if !ok || record.ExpiresAt > now {
			return pruned
		}
		delete(c.agentsByID, record.ID)
		c.agentsByExpiresAt.Delete(record)
		pruned++
	}
}

func (c *Cache) appendDescendents(records []api.ReadOnlyEntry, parentID string, parentSeen stringSet) []api.ReadOnlyEntry {
	if _, ok := parentSeen[parentID]; ok {
		return records
	}
	parentSeen[parentID] = struct{}{}

	parentEntries := c.entriesByParentID[parentID]
	for _, entry := range parentEntries {
		records = append(records, api.NewReadOnlyEntry(entry))
		records = c.appendDescendents(records, entry.SpiffeId.Path, parentSeen)
	}
	return records
}

func (c *Cache) addDescendants(foundEntries map[string]api.ReadOnlyEntry, parentID string, requestedEntries map[string]struct{}, parentSeen stringSet) {
	if _, ok := parentSeen[parentID]; ok {
		return
	}
	parentSeen[parentID] = struct{}{}

	parentEntries := c.entriesByParentID[parentID]
	for _, entry := range parentEntries {
		if _, ok := requestedEntries[entry.Id]; ok {
			foundEntries[entry.Id] = api.NewReadOnlyEntry(entry)
		}

		if len(foundEntries) == len(requestedEntries) {
			return
		}

		c.addDescendants(foundEntries, entry.SpiffeId.Path, requestedEntries, parentSeen)
	}
}

func (c *Cache) getAgentAliases(agentSelectors selectorSet) []aliasRecord {
	// Keep track of which aliases have already been evaluated.
	aliasesSeen := allocStringSet()
	defer freeStringSet(aliasesSeen)

	// Figure out which aliases the agent belongs to.
	var aliasIDs []aliasRecord
	for agentSelector := range agentSelectors {
		pivot := aliasRecord{Selector: agentSelector}
		c.aliasesBySelector.AscendGreaterOrEqual(pivot, func(record aliasRecord) bool {
			if record.Selector != agentSelector {
				return false
			}
			if _, ok := aliasesSeen[record.EntryID]; ok {
				return true
			}
			aliasesSeen[record.EntryID] = struct{}{}
			if isSubset(record.AllSelectors, agentSelectors) {
				aliasIDs = append(aliasIDs, record)
			}
			return true
		})
	}
	return aliasIDs
}

func (c *Cache) updateEntry(entry *types.Entry) {
	if isNodeAlias(entry) {
		ar := aliasRecord{
			EntryID:      entry.Id,
			AliasID:      entry.SpiffeId.Path,
			AllSelectors: selectorSetFromProto(entry.Selectors),
		}
		for selector := range ar.AllSelectors {
			ar.Selector = selector
			c.aliasesByEntryID.ReplaceOrInsert(ar)
			c.aliasesBySelector.ReplaceOrInsert(ar)
		}
		return
	}

	c.entriesByEntryID[entry.Id] = entry
	parentEntries, ok := c.entriesByParentID[entry.ParentId.Path]
	if !ok {
		c.entriesByParentID[entry.ParentId.Path] = make(map[string]*types.Entry)
		parentEntries = c.entriesByParentID[entry.ParentId.Path]
	}

	c.entriesByEntryID[entry.Id] = entry
	parentEntries[entry.Id] = entry
}

func (c *Cache) removeEntry(entryID string) {
	entry, ok := c.entriesByEntryID[entryID]
	if ok {
		delete(c.entriesByEntryID, entryID)
		parentEntries, ok := c.entriesByParentID[entry.ParentId.Path]
		if ok {
			delete(parentEntries, entryID)
			if len(parentEntries) == 0 {
				delete(c.entriesByParentID, entry.ParentId.Path)
			}
		}
	}

	var aliasRecordsToDelete []aliasRecord
	aliasPivot := aliasRecord{EntryID: entryID}
	c.aliasesByEntryID.AscendGreaterOrEqual(aliasPivot, func(record aliasRecord) bool {
		if record.EntryID != entryID {
			return false
		}
		aliasRecordsToDelete = append(aliasRecordsToDelete, record)
		return true
	})

	for _, record := range aliasRecordsToDelete {
		c.aliasesByEntryID.Delete(record)
		c.aliasesBySelector.Delete(record)
	}
}

func (c *Cache) Stats() CacheStats {
	entryByParentIDCount := 0
	c.mu.RLock()
	for _, entries := range c.entriesByParentID {
		entryByParentIDCount += len(entries)
	}
	c.mu.RUnlock()

	return CacheStats{
		AgentsByID:        len(c.agentsByID),
		AgentsByExpiresAt: c.agentsByExpiresAt.Len(),
		AliasesByEntryID:  c.aliasesByEntryID.Len(),
		AliasesBySelector: c.aliasesBySelector.Len(),
		EntriesByEntryID:  len(c.entriesByEntryID),
		EntriesByParentID: entryByParentIDCount,
	}
}

func isNodeAlias(e *types.Entry) bool {
	return e.ParentId.Path == idutil.ServerIDPath
}

type CacheStats struct {
	AgentsByID        int
	AgentsByExpiresAt int
	AliasesByEntryID  int
	AliasesBySelector int
	EntriesByEntryID  int
	EntriesByParentID int
}
