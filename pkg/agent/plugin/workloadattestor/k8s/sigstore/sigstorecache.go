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

//
type MapItem struct {
	element *list.Element
	item    *Item
}

// cache implements Cache interface
type Cacheimpl struct {
	size     int
	items    *list.List
	mutex    sync.RWMutex
	itensMap map[string]MapItem
}

// NewCache creates and returns a new cache
func NewCache(maximumAmountCache int) Cache {
	return &Cacheimpl{
		size:     maximumAmountCache,
		items:    list.New(),
		mutex:    sync.RWMutex{},
		itensMap: make(map[string]MapItem),
	}
}

// Get returns an existing item from the cache.
// Get also moves the existing item to the front of the items list to indicate that the existing item is recently used.
func (c *Cacheimpl) GetSignature(key string) *Item {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	e, present := c.itensMap[key]
	if !present {
		return nil
	}

	c.items.MoveToFront(e.element)

	return e.item
}

// Put puts a new item into the cache.
// Put removes the least recently used item from the items list when the cache is full.
// Put pushes the new item to the front of the items list to indicate that the new item is recently used.
func (c *Cacheimpl) PutSignature(i Item) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	e, present := c.itensMap[i.Key]
	if present {
		c.items.Remove(e.element)
		c.itensMap[i.Key] = MapItem{
			element: c.items.PushFront(i.Key),
			item:    &i,
		}
	} else {
		if c.items.Len() == c.size {
			removed := c.items.Remove(c.items.Back())
			delete(c.itensMap, removed.(string))
		}

		c.itensMap[i.Key] = MapItem{
			element: c.items.PushFront(i.Key),
			item:    &i,
		}
	}
}
