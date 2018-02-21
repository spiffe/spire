package cache

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"hash"
	"sort"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/common"
)

type Selectors []*common.Selector

// Entry holds the data of a single cache entry.
type Entry struct {
	RegistrationEntry *common.RegistrationEntry
	SVID              *x509.Certificate
	PrivateKey        *ecdsa.PrivateKey

	// Bundles stores the ID => Bundle map for
	// federated bundles. The registration entry
	// only stores references to the keys here.
	Bundles map[string][]byte
}

type Cache interface {
	Entry([]*common.Selector) (entry []Entry)
	SetEntry(cacheEntry Entry)
	DeleteEntry([]*common.Selector) (deleted bool)
	// Entries returns the current cached entries state.
	Entries() map[string][]Entry
	MatchingEntries([]*common.Selector) (entry []Entry)
}

type cacheImpl struct {
	cache map[string][]Entry
	log   logrus.FieldLogger
	m     sync.Mutex
}

func NewCache(Logger logrus.FieldLogger) *cacheImpl {
	return &cacheImpl{cache: make(map[string][]Entry),
		log: Logger.WithField("subsystem_name", "cache")}
}

func (c *cacheImpl) Entries() map[string][]Entry {
	// We make a copy of the current cache state to prevent:
	// 1) Callers to be affected by future cache modifications when iterating
	// over the returned entries.
	// 2) The cache itself to be affected by external modifications that could be
	// done to the returned entries.
	c.m.Lock()
	defer c.m.Unlock()
	entries := map[string][]Entry{}
	for k, e := range c.cache {
		entries[k] = make([]Entry, len(e))
		copy(entries[k], c.cache[k])
	}
	return entries

}

func (c *cacheImpl) Entry(selectors []*common.Selector) (entry []Entry) {
	key := deriveCacheKey(selectors)
	c.m.Lock()
	defer c.m.Unlock()
	if entry, found := c.cache[key]; found {
		return entry
	}
	return nil
}

// MatchingEntries takes a slice of selectors, and works through all the combinations in order to
// find matching cache entries
func (c *cacheImpl) MatchingEntries(selectors []*common.Selector) (entries []Entry) {
	selectorSet := selector.NewSet(selectors)
	c.m.Lock()
	defer c.m.Unlock()

	for subSet := range selectorSet.Power() {
		key := deriveCacheKey(subSet.Raw())
		if entry, found := c.cache[key]; found {
			entries = append(entries, entry...)
		}
	}
	return entries
}

func (c *cacheImpl) SetEntry(cacheEntry Entry) {
	c.m.Lock()
	defer c.m.Unlock()
	key := deriveCacheKey(cacheEntry.RegistrationEntry.Selectors)

	for i, entry := range c.cache[key] {
		if entry.RegistrationEntry.SpiffeId == cacheEntry.RegistrationEntry.SpiffeId {
			copy(c.cache[key][i:], c.cache[key][i+1:])
			c.cache[key][len(c.cache[key])-1] = Entry{}
			c.cache[key] = c.cache[key][:len(c.cache[key])-1]
			break
		}
	}
	c.cache[key] = append(c.cache[key], cacheEntry)
	return

}

func (c *cacheImpl) DeleteEntry(selectors []*common.Selector) (deleted bool) {
	c.m.Lock()
	defer c.m.Unlock()
	key := deriveCacheKey(selectors)
	if _, exists := c.cache[key]; exists == true {
		delete(c.cache, key)
		deleted = true
	}
	return
}

func deriveCacheKey(s Selectors) (key string) {
	var concatSelectors string
	sort.Slice(s, util.SelectorsSortFunction(s))

	for _, selector := range s {
		concatSelectors = concatSelectors + "::" + selector.Type + ":" + selector.Value
	}
	hashedSelectors := hash.Hash.Sum(sha256.New(), []byte(concatSelectors))

	return string(hashedSelectors)
}
