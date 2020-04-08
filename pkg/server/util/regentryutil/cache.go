package regentryutil

import (
	"fmt"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/spiffe/spire/proto/spire/common"
)

type RegistrationEntriesCache interface {
	Get(key string) ([]*common.RegistrationEntry, bool)
	AddWithExpire(key string, value []*common.RegistrationEntry, expire time.Duration)
}

// FetchRegistrationEntriesCache is a wrapper around LRU cache with expiry, used for caching registration entries of a agent
type FetchRegistrationEntriesCache struct {
	Cache   *lru.Cache
	TimeNow func() time.Time

	mu sync.RWMutex
}

type cacheValue struct {
	entries   []*common.RegistrationEntry
	expiresAt time.Time
}

func NewFetchX509SVIDCache(cacheSize int) (*FetchRegistrationEntriesCache, error) {
	cache, err := lru.New(cacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create lru cache: %v", err)
	}
	return &FetchRegistrationEntriesCache{
		Cache:   cache,
		TimeNow: time.Now,
	}, nil
}

func (c *FetchRegistrationEntriesCache) Get(key string) ([]*common.RegistrationEntry, bool) {
	c.mu.RLock()
	ifc, ok := c.Cache.Get(key)
	if !ok {
		c.mu.RUnlock()
		return nil, false
	}
	value, ok := ifc.(*cacheValue)
	if !ok {
		c.mu.RUnlock()
		return nil, false
	}
	if c.TimeNow().After(value.expiresAt) {
		c.mu.RUnlock()
		c.processExpiredEntry(key)
		return nil, false
	}
	c.mu.RUnlock()
	return value.entries, true
}

func (c *FetchRegistrationEntriesCache) processExpiredEntry(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ifc, ok := c.Cache.Get(key)
	if !ok {
		return
	}
	value, ok := ifc.(*cacheValue)
	if !ok {
		return
	}
	if c.TimeNow().After(value.expiresAt) {
		c.Cache.Remove(key)
	}
}

func (c *FetchRegistrationEntriesCache) AddWithExpire(key string, value []*common.RegistrationEntry, expire time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Cache.Add(key, &cacheValue{
		entries:   value,
		expiresAt: c.TimeNow().Add(expire),
	})
}
