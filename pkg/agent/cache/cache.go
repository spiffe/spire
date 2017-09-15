package cache

import (
	"crypto/sha256"
	"hash"
	"sort"
	"sync"

	"crypto/ecdsa"
	"github.com/spiffe/spire/pkg/api/node"
	"github.com/spiffe/spire/pkg/common"
	"github.com/spiffe/spire/pkg/common/util"
)

type selectors []*common.Selector

type CacheEntry struct {
	RegistrationEntry *common.RegistrationEntry
	SVID              *node.Svid
	PrivateKey        *ecdsa.PrivateKey
}

type Cache interface {
	Entry([]*common.Selector) (entry []CacheEntry)
	SetEntry(cacheEntry CacheEntry)
	DeleteEntry([]*common.Selector) (deleted bool)
}

type cacheImpl struct {
	cache map[string][]CacheEntry
	m     sync.Mutex
}

func NewCache() *cacheImpl {
	return &cacheImpl{cache: make(map[string][]CacheEntry)}
}

func (c *cacheImpl) Entry(selectors []*common.Selector) (entry []CacheEntry) {
	key := deriveCacheKey(selectors)
	c.m.Lock()
	defer c.m.Unlock()
	return c.cache[key]
}

func (c *cacheImpl) SetEntry(cacheEntry CacheEntry) {
	c.m.Lock()
	defer c.m.Unlock()
	key := deriveCacheKey(cacheEntry.RegistrationEntry.Selectors)
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

func deriveCacheKey(s selectors) (key string) {
	var concatSelectors string
	sort.Slice(s, util.SelectorsSortFunction(s))

	for _, selector := range s {
		concatSelectors = concatSelectors + "::" + selector.Type + ":" + selector.Value
	}
	hashedSelectors := hash.Hash.Sum(sha256.New(), []byte(concatSelectors))

	return string(hashedSelectors)
}
