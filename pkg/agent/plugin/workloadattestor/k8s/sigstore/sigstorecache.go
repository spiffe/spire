//go:build !windows

package sigstore

import (
	"container/list"
	"sync"
)

// Item represents a key-value pair
type Item struct {
	Key   string
	Value []SelectorsFromSignatures
}

// Cache defines the behaviors of our cache
type Cache interface {
	GetSignature(key string) *Item
	PutSignature(Item)
}

// Map for signatures is created
type MapItem struct {
	element *list.Element
	item    *Item
}

// cacheImpl implements Cache interface
type cacheImpl struct {
	size     int
	items    *list.List
	mutex    sync.RWMutex
	itemsMap map[string]MapItem
}

// NewCache creates and returns a new cache
func NewCache(maximumAmountCache int) Cache {
	return &cacheImpl{
		size:     maximumAmountCache,
		items:    list.New(),
		mutex:    sync.RWMutex{},
		itemsMap: make(map[string]MapItem),
	}
}

// GetSignature returns an existing item from the cache.
// Get also moves the existing item to the front of the items list to indicate that the existing item is recently used.
func (c *cacheImpl) GetSignature(key string) *Item {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	e, ok := c.itemsMap[key]
	if !ok {
		return nil
	}

	c.items.MoveToFront(e.element)

	return e.item
}

// PutSignature puts a new item into the cache.
// Put removes the least recently used item from the items list when the cache is full.
// Put pushes the new item to the front of the items list to indicate that the new item is recently used.
func (c *cacheImpl) PutSignature(i Item) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	e, ok := c.itemsMap[i.Key]
	if ok {
		c.items.Remove(e.element)
		c.itemsMap[i.Key] = MapItem{
			element: c.items.PushFront(i.Key),
			item:    &i,
		}
		return
	}
	if c.items.Len() >= c.size {
		removed := c.items.Remove(c.items.Back())
		delete(c.itemsMap, removed.(string))
	}

	c.itemsMap[i.Key] = MapItem{
		element: c.items.PushFront(i.Key),
		item:    &i,
	}
}
