package agent

import (
	"crypto/sha256"
	"hash"
	"sort"
	"sync"

	"crypto/ecdsa"
	"github.com/spiffe/spire/pkg/api/node"
	"github.com/spiffe/spire/pkg/common"
)

type selectors []*common.Selector

func (s selectors) Len() int      { return len(s) }
func (s selectors) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s selectors) Less(i, j int) bool {
	if s[i].Type != s[j].Type {
		return s[i].Type < s[j].Type
	} else {
		return s[i].Value < s[j].Value
	}
}

type CacheEntry struct {
	registrationEntry *common.RegistrationEntry
	SVID              *node.Svid
	privateKey        *ecdsa.PrivateKey
}

type Cache interface {
	Entry([]*common.Selector) (entry []CacheEntry)
	SetEntry(cacheEntry CacheEntry)
	DeleteEntry([]*common.Selector) (deleted bool)
}

type CacheImpl struct {
	cache map[string][]CacheEntry
	m     sync.Mutex
}

func NewCache() *CacheImpl {
	return &CacheImpl{cache: make(map[string][]CacheEntry)}
}

func (c *CacheImpl) Entry(selectors []*common.Selector) (entry []CacheEntry) {
	key := deriveCacheKey(selectors)
	c.m.Lock()
	defer c.m.Unlock()
	return c.cache[key]
}

func (c *CacheImpl) SetEntry(cacheEntry CacheEntry) {
	c.m.Lock()
	defer c.m.Unlock()
	key := deriveCacheKey(cacheEntry.registrationEntry.Selectors)
	c.cache[key] = append(c.cache[key], cacheEntry)
	return

}

func (c *CacheImpl) DeleteEntry(selectors []*common.Selector) (deleted bool) {
	c.m.Lock()
	defer c.m.Unlock()
	key := deriveCacheKey(selectors)
	if _, exists := c.cache[key]; exists == true {
		delete(c.cache, key)
		deleted = true
	}
	return
}

func deriveCacheKey(selectors selectors) (key string) {
	var concatSelectors string
	sort.Sort(selectors)
	for _, selector := range selectors {
		concatSelectors = concatSelectors + "::" + selector.Type + ":" + selector.Value
	}
	hashedSelectors := hash.Hash.Sum(sha256.New(), []byte(concatSelectors))

	return string(hashedSelectors)
}
