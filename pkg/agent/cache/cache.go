package cache

import (
	"crypto/sha256"
	"hash"
	"sort"
	"sync"
	"time"

	"crypto/ecdsa"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
)

type selectors []*common.Selector

type CacheEntry struct {
	RegistrationEntry *common.RegistrationEntry
	SVID              *node.Svid
	PrivateKey        *ecdsa.PrivateKey
	Expiry            time.Time

	// Bundles stores the ID => Bundle map for
	// federated bundles. The registration entry
	// only stores references to the keys here.
	Bundles map[string][]byte
}

type Cache interface {
	Entry([]*common.Selector) (entry []CacheEntry)
	SetEntry(cacheEntry CacheEntry)
	DeleteEntry([]*common.Selector) (deleted bool)
	Entries() map[string][]CacheEntry
}

type cacheImpl struct {
	cache map[string][]CacheEntry
	log   logrus.FieldLogger
	m     sync.Mutex
}

func NewCache(Logger logrus.FieldLogger) *cacheImpl {
	return &cacheImpl{cache: make(map[string][]CacheEntry),
		log: Logger.WithField("subsystem_name", "cache")}
}

func (c *cacheImpl) Entries() map[string][]CacheEntry {
	c.m.Lock()
	defer c.m.Unlock()
	return c.cache

}

func (c *cacheImpl) Entry(selectors []*common.Selector) (entry []CacheEntry) {
	key := deriveCacheKey(selectors)
	c.m.Lock()
	defer c.m.Unlock()
	if entry, found := c.cache[key]; found {
		return entry
	}
	return nil
}

func (c *cacheImpl) SetEntry(cacheEntry CacheEntry) {
	c.m.Lock()
	defer c.m.Unlock()
	key := deriveCacheKey(cacheEntry.RegistrationEntry.Selectors)

	for i, entry := range c.cache[key] {
		if entry.RegistrationEntry.SpiffeId == cacheEntry.RegistrationEntry.SpiffeId {
			copy(c.cache[key][i:], c.cache[key][i+1:])
			c.cache[key][len(c.cache[key])-1] = CacheEntry{}
			c.cache[key] = c.cache[key][:len(c.cache[key])-1]
			break
		}
	}
	c.cache[key] = append(c.cache[key], cacheEntry)
	c.log.Debug("len(c.cache):", len(c.cache))
	c.log.Debug("selectors:", cacheEntry.RegistrationEntry.Selectors, "len(c.cache[key]):", len(c.cache[key]))
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

func deriveCacheKey(s selectors) (key string) {
	var concatSelectors string
	sort.Slice(s, util.SelectorsSortFunction(s))

	for _, selector := range s {
		concatSelectors = concatSelectors + "::" + selector.Type + ":" + selector.Value
	}
	hashedSelectors := hash.Hash.Sum(sha256.New(), []byte(concatSelectors))

	return string(hashedSelectors)
}
