package authorizedentries

import (
	"fmt"
	"sync"

	"github.com/google/btree"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

const (
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

	agents map[string]selectorSet

	aliasesByEntryID  *btree.BTreeG[aliasRecord]
	aliasesBySelector *btree.BTreeG[aliasRecord]

	entriesByEntryID  *btree.BTreeG[entryRecord]
	entriesByParentID *btree.BTreeG[entryRecord]
}

func NewCache() *Cache {
	return &Cache{
		agents:            make(map[string]selectorSet),
		aliasesByEntryID:  btree.NewG(aliasRecordDegree, aliasRecordByEntryID),
		aliasesBySelector: btree.NewG(aliasRecordDegree, aliasRecordBySelector),
		entriesByEntryID:  btree.NewG(entryDegree, entryRecordByEntryID),
		entriesByParentID: btree.NewG(entryDegree, entryRecordByParentID),
	}
}

func (c *Cache) GetAuthorizedEntries(agentID spiffeid.ID) []*types.Entry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	agentSelectors, ok := c.getAgentSelectors(agentID.String())
	if !ok {
		// agent is not attested or has expired
		return nil
	}

	parentSeen := allocStringSet()
	defer freeStringSet(parentSeen)

	records := allocRecordSlice()
	defer freeRecordSlice(records)

	records = c.appendDescendents(records, agentID.String(), parentSeen)

	agentAliases := c.getAgentAliases(agentSelectors)
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

func (c *Cache) SetNodeSelectors(agentID string, selectors []*types.Selector) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(selectors) > 0 {
		c.agents[agentID] = selectorSetFromProto(selectors)
	} else {
		delete(c.agents, agentID)
	}
}

func (c *Cache) appendDescendents(records []entryRecord, parentID string, parentSeen stringSet) []entryRecord {
	if _, ok := parentSeen[parentID]; ok {
		return records
	}
	parentSeen[parentID] = struct{}{}

	before := records
	records = c.appendEntryRecordsForParentID(records, parentID)
	// Crawl the children that were appended to get their descendents
	for _, entry := range records[len(before):] {
		records = c.appendDescendents(records, entry.SPIFFEID, parentSeen)
	}
	return records
}

func (c *Cache) getAgentSelectors(agentID string) (selectorSet, bool) {
	selectors, ok := c.agents[agentID]
	return selectors, ok
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
	} else {
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

func spiffeIDFromProto(id *types.SPIFFEID) string {
	return fmt.Sprintf("spiffe://%s%s", id.TrustDomain, id.Path)
}

func isNodeAlias(e *types.Entry) bool {
	return e.ParentId.Path == "/spire/server"
}
