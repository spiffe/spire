package authorizedentries

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/btree"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/idutil"
)

const (
	// We can tweak these degrees to try and get optimal L1 cache use but
	// it's probably not worth it unless we have benchmarks showing that it
	// is a problem at scale in production. Initial benchmarking by myself
	// at similar scale to some of our bigger, existing deployments didn't
	// seem to yield much difference. As such, these values are probably an
	// ok jumping off point.
	agentRecordDegree = 32
	aliasRecordDegree = 32
	entryDegree       = 32
)

type Selector struct {
	Type  string
	Value string
}

func (s Selector) String() string {
	return s.Type + ":" + s.Value
}

type Cache struct {
	mu sync.RWMutex

	agentsByID        *btree.BTreeG[agentRecord]
	agentsByExpiresAt *btree.BTreeG[agentRecord]

	aliasesByEntryID  *btree.BTreeG[aliasRecord]
	aliasesBySelector *btree.BTreeG[aliasRecord]

	entriesByEntryID  *btree.BTreeG[entryRecord]
	entriesByParentID *btree.BTreeG[entryRecord]
}

func NewCache() *Cache {
	return &Cache{
		agentsByID:        btree.NewG(agentRecordDegree, agentRecordByID),
		agentsByExpiresAt: btree.NewG(agentRecordDegree, agentRecordByExpiresAt),
		aliasesByEntryID:  btree.NewG(aliasRecordDegree, aliasRecordByEntryID),
		aliasesBySelector: btree.NewG(aliasRecordDegree, aliasRecordBySelector),
		entriesByEntryID:  btree.NewG(entryDegree, entryRecordByEntryID),
		entriesByParentID: btree.NewG(entryDegree, entryRecordByParentID),
	}
}

func (c *Cache) GetAuthorizedEntries(agentID spiffeid.ID) []*types.Entry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Load up the agent selectors. If the agent info does not exist, it is
	// likely that the cache is still catching up to a recent attestation.
	// Since the calling agent has already been authorized and authenticated,
	// it is safe to continue with the authorized entry crawl to obtain entries
	// that are directly parented against the agent. Any entries that would be
	// obtained via node aliasing will not be returned until the cache is
	// updated with the node selectors for the agent.
	agent, _ := c.agentsByID.Get(agentRecord{ID: agentID.String()})

	parentSeen := allocStringSet()
	defer freeStringSet(parentSeen)

	records := allocRecordSlice()
	defer freeRecordSlice(records)

	records = c.appendDescendents(records, agentID.String(), parentSeen)

	agentAliases := c.getAgentAliases(agent.Selectors)
	for _, alias := range agentAliases {
		records = c.appendDescendents(records, alias.AliasID, parentSeen)
	}

	return cloneEntriesFromRecords(records)
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
	c.mu.Lock()
	defer c.mu.Unlock()

	agent := agentRecord{
		ID:        agentID,
		ExpiresAt: expiresAt.Unix(),
		Selectors: selectorSetFromProto(selectors),
	}

	// Need to delete existing record from the ExpiresAt index first. Use
	// the ID index to locate the existing record.
	if existing, exists := c.agentsByID.Get(agent); exists {
		c.agentsByExpiresAt.Delete(existing)
	}

	c.agentsByID.ReplaceOrInsert(agent)
	c.agentsByExpiresAt.ReplaceOrInsert(agent)
}

func (c *Cache) RemoveAgent(agentID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if agent, exists := c.agentsByID.Get(agentRecord{ID: agentID}); exists {
		c.agentsByID.Delete(agent)
		c.agentsByExpiresAt.Delete(agent)
	}
}

func (c *Cache) PruneExpiredAgents() int {
	now := time.Now().Unix()
	pruned := 0

	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		record, ok := c.agentsByExpiresAt.Min()
		if !ok || record.ExpiresAt > now {
			return pruned
		}
		c.agentsByID.Delete(record)
		c.agentsByExpiresAt.Delete(record)
		pruned++
	}
}

func (c *Cache) appendDescendents(records []entryRecord, parentID string, parentSeen stringSet) []entryRecord {
	if _, ok := parentSeen[parentID]; ok {
		return records
	}
	parentSeen[parentID] = struct{}{}

	lenBefore := len(records)
	records = c.appendEntryRecordsForParentID(records, parentID)
	// Crawl the children that were appended to get their descendents
	for _, entry := range records[lenBefore:] {
		records = c.appendDescendents(records, entry.SPIFFEID, parentSeen)
	}
	return records
}

func (c *Cache) appendEntryRecordsForParentID(records []entryRecord, parentID string) []entryRecord {
	pivot := entryRecord{ParentID: parentID}
	c.entriesByParentID.AscendGreaterOrEqual(pivot, func(record entryRecord) bool {
		if record.ParentID != parentID {
			return false
		}
		records = append(records, record)
		return true
	})
	return records
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
			AliasID:      spiffeIDFromProto(entry.SpiffeId),
			AllSelectors: selectorSetFromProto(entry.Selectors),
		}
		for selector := range ar.AllSelectors {
			ar.Selector = selector
			c.aliasesByEntryID.ReplaceOrInsert(ar)
			c.aliasesBySelector.ReplaceOrInsert(ar)
		}
		return
	}

	er := entryRecord{
		EntryID:  entry.Id,
		SPIFFEID: spiffeIDFromProto(entry.SpiffeId),
		ParentID: spiffeIDFromProto(entry.ParentId),
		// For quick cloning at the end of the crawl so we don't have to have
		// a separate data structure for looking up entries by id.
		EntryCloneOnly: entry,
	}
	c.entriesByParentID.ReplaceOrInsert(er)
	c.entriesByEntryID.ReplaceOrInsert(er)
}

func (c *Cache) removeEntry(entryID string) {
	entryPivot := entryRecord{EntryID: entryID}

	var entryRecordsToDelete []entryRecord
	c.entriesByEntryID.AscendGreaterOrEqual(entryPivot, func(record entryRecord) bool {
		if record.EntryID != entryID {
			return false
		}
		entryRecordsToDelete = append(entryRecordsToDelete, record)
		return true
	})

	for _, record := range entryRecordsToDelete {
		c.entriesByEntryID.Delete(record)
		c.entriesByParentID.Delete(record)
	}

	if len(entryRecordsToDelete) > 0 {
		// entry was a normal workload registration. No need to search the aliases.
		return
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

func (c *Cache) stats() cacheStats {
	return cacheStats{
		AgentsByID:        c.agentsByID.Len(),
		AgentsByExpiresAt: c.agentsByExpiresAt.Len(),
		AliasesByEntryID:  c.aliasesByEntryID.Len(),
		AliasesBySelector: c.aliasesBySelector.Len(),
		EntriesByEntryID:  c.entriesByEntryID.Len(),
		EntriesByParentID: c.entriesByParentID.Len(),
	}
}

func spiffeIDFromProto(id *types.SPIFFEID) string {
	return fmt.Sprintf("spiffe://%s%s", id.TrustDomain, id.Path)
}

func isNodeAlias(e *types.Entry) bool {
	return e.ParentId.Path == idutil.ServerIDPath
}

type cacheStats struct {
	AgentsByID        int
	AgentsByExpiresAt int
	AliasesByEntryID  int
	AliasesBySelector int
	EntriesByEntryID  int
	EntriesByParentID int
}
