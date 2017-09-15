package cache

import (
	"crypto/sha256"
	"hash"
	"sort"
	"sync"
	"time"

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

func deriveCacheKey(selectors selectors) (key string) {
	var concatSelectors string
	sort.Sort(selectors)
	for _, selector := range selectors {
		concatSelectors = concatSelectors + "::" + selector.Type + ":" + selector.Value
	}
	hashedSelectors := hash.Hash.Sum(sha256.New(), []byte(concatSelectors))

	return string(hashedSelectors)
}
