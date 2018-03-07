package cache

import (
	"crypto/ecdsa"
	"crypto/x509"
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
	// Entry gets the first cache entry for the specified RegistrationEntry.
	Entry(regEntry *common.RegistrationEntry) *Entry
	// SetEntry puts a new cache entry at the end of the list of entries for the entry's RegistrationEntry.
	SetEntry(entry *Entry)
	// DeleteEntries deletes all the Entries for the specified RegistrationEntry, returns an integer
	// with the number of cache entries that were removed.
	DeleteEntries(regEntry *common.RegistrationEntry) int
	// DeleteEntry removes the first cache entry for the specified RegistrationEntry if any,
	// returns true if it removed some entry or false otherwise.
	DeleteEntry(regEntry *common.RegistrationEntry) bool
	// Entries returns all the in force cached entries.
	Entries() chan Entry
	// IsEmpty returns true if this cache doesn't have any entry.
	IsEmpty() bool
	// Register a Subscriber and return WorkloadUpdate on the subscriber's channel
	Subscribe(sub *Subscriber)
}

type cacheImpl struct {
	// Map keyed by a combination of SpiffeId + ParentId + Selectors holding a list of
	// Entry instances ordered by SVID expiration date.
	cache       map[string][]Entry
	log         logrus.FieldLogger
	m           sync.Mutex
	Subscribers *subscribers
	bundle      []*x509.Certificate
}

// New creates a new Cache.
func New(log logrus.FieldLogger, bundle []*x509.Certificate) Cache {
	return &cacheImpl{
		cache:       make(map[string][]Entry),
		log:         log.WithField("subsystem_name", "cache"),
		bundle:      bundle,
		Subscribers: NewSubscribers(),
	}
}

func (c *cacheImpl) SetServerBundle(bundle []*x509.Certificate) {
	c.m.Lock()
	defer c.m.Unlock()
	c.bundle = bundle
}

func (c *cacheImpl) serverBundle() []*x509.Certificate {
	c.m.Lock()
	defer c.m.Unlock()
	return c.bundle
}

func (c *cacheImpl) Entries() chan Entry {
	c.m.Lock()
	defer c.m.Unlock()
	entries := make(chan Entry, len(c.cache))
	for _, e := range c.cache {
		// Only return the first element for each array of entries because it is the
		// in force entry.
		entries <- e[0]
	}
	close(entries)
	return entries
}

func (c *cacheImpl) Subscribe(sub *Subscriber) {
	entries := c.Entries()
	c.m.Lock()
	defer c.m.Unlock()
	go c.updateSubscrbers([]*Subscriber{sub}, entries)
	c.Subscribers.Add(sub)
}

func (c *cacheImpl) Entry(regEntry *common.RegistrationEntry) *Entry {
	key := util.DeriveRegEntryhash(regEntry)
	c.m.Lock()
	defer c.m.Unlock()
	if entries, found := c.cache[key]; found {
		return &entries[0]
	}
	return nil
}

func (c *cacheImpl) SetEntry(entry *Entry) {
	entries := c.Entries()
	c.m.Lock()
	defer c.m.Unlock()

	key := util.DeriveRegEntryhash(entry.RegistrationEntry)
	c.cache[key] = append(c.cache[key], *entry)

	subs := c.Subscribers.Get(entry.RegistrationEntry.Selectors)
	c.updateSubscrbers(subs, entries)
	return
}

func (c *cacheImpl) updateSubscrbers(subs []*Subscriber, entryCh chan Entry) {
	for _, sub := range subs {
		subEntries := SubscriberEntries(sub, entryCh)
		select {
		case <-sub.done:
			c.Subscribers.remove(sub)
		case sub.C <- &WorkloadUpdate{Entries: subEntries, Bundle: c.bundle}:
		}
	}
}
func (c *cacheImpl) DeleteEntries(regEntry *common.RegistrationEntry) (numOfEntries int) {
	c.m.Lock()
	var subs []*Subscriber
	key := util.DeriveRegEntryhash(regEntry)
	if entries, found := c.cache[key]; found {
		subs = c.Subscribers.Get(entries[0].RegistrationEntry.Selectors)
		delete(c.cache, key)
		numOfEntries = len(entries)
	}
	c.m.Unlock()
	if numOfEntries > 0 {
		c.updateSubscrbers(subs, c.Entries())
	}
	return
}

func (c *cacheImpl) DeleteEntry(regEntry *common.RegistrationEntry) (deleted bool) {
	c.m.Lock()
	var subs []*Subscriber
	key := util.DeriveRegEntryhash(regEntry)
	if entries, found := c.cache[key]; found {
		subs = c.Subscribers.Get(entries[0].RegistrationEntry.Selectors)
		if len(entries) > 0 {
			c.cache[key] = entries[1:]
			if len(c.cache[key]) == 0 {
				delete(c.cache, key)
			}
			deleted = true
		}
	}
	c.m.Unlock()
	if deleted {
		c.updateSubscrbers(subs, c.Entries())
	}
	return
}

func (c *cacheImpl) IsEmpty() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return len(c.cache) == 0
}

func SubscriberEntries(sub *Subscriber, entryCh chan Entry) (entries []Entry) {
	for e := range entryCh {
		regEntrySelectors := selector.NewSetFromRaw(e.RegistrationEntry.Selectors)
		if selector.NewSetFromRaw(sub.sel).IncludesSet(regEntrySelectors) {
			entries = append(entries, e)
		}
	}
	return
}
