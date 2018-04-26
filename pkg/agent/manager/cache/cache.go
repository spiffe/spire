package cache

import (
	"crypto/ecdsa"
	"crypto/x509"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/selector"
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
	// Entry gets the cache entry for the specified RegistrationEntry.
	Entry(regEntry *common.RegistrationEntry) *Entry
	// SetEntry puts a new cache entry for the entry's RegistrationEntry.
	SetEntry(entry *Entry)
	// DeleteEntry removes the cache entry for the specified RegistrationEntry if it exists,
	// returns true if it removed some entry or false otherwise.
	DeleteEntry(regEntry *common.RegistrationEntry) bool
	// Entries returns all the in force cached entries.
	Entries() []*Entry
	// IsEmpty returns true if this cache doesn't have any entry.
	IsEmpty() bool
	// Register a Subscriber and return WorkloadUpdate on the subscriber's channel
	Subscribe(sub *Subscriber)
	// Set the bundle
	SetBundle([]*x509.Certificate)
	// Retrieve the bundle
	Bundle() []*x509.Certificate
}

type cacheImpl struct {
	// Map keyed by RegistrationEntry.EntryId holding Entry instances.
	cache       map[string]*Entry
	log         logrus.FieldLogger
	m           sync.Mutex
	Subscribers *subscribers
	bundle      []*x509.Certificate
}

// New creates a new Cache.
func New(log logrus.FieldLogger, bundle []*x509.Certificate) Cache {
	return &cacheImpl{
		cache:       make(map[string]*Entry),
		log:         log.WithField("subsystem_name", "cache"),
		bundle:      bundle,
		Subscribers: NewSubscribers(),
	}
}

func (c *cacheImpl) SetBundle(bundle []*x509.Certificate) {
	c.m.Lock()
	c.bundle = bundle
	c.m.Unlock()

	subs := c.Subscribers.GetAll()
	c.notifySubscribers(subs)
}

func (c *cacheImpl) Bundle() []*x509.Certificate {
	c.m.Lock()
	defer c.m.Unlock()
	return c.bundle
}

func (c *cacheImpl) Entries() []*Entry {
	c.m.Lock()
	defer c.m.Unlock()
	entries := []*Entry{}
	for _, e := range c.cache {
		entries = append(entries, e)
	}
	return entries
}

func (c *cacheImpl) Subscribe(sub *Subscriber) {
	c.Subscribers.Add(sub)
	c.notifySubscribers([]*Subscriber{sub})
}

func (c *cacheImpl) Entry(regEntry *common.RegistrationEntry) *Entry {
	c.m.Lock()
	defer c.m.Unlock()
	if entry, found := c.cache[regEntry.EntryId]; found {
		return entry
	}
	return nil
}

func (c *cacheImpl) SetEntry(entry *Entry) {
	c.m.Lock()
	c.cache[entry.RegistrationEntry.EntryId] = entry
	c.m.Unlock()

	subs := c.Subscribers.Get(entry.RegistrationEntry.Selectors)
	c.notifySubscribers(subs)
}

func (c *cacheImpl) notifySubscribers(subs []*Subscriber) {
	go func() {
		entries := c.Entries()
		bundle := c.Bundle()
		for _, sub := range subs {
			subEntries := subscriberEntries(sub, entries)
			select {
			case <-sub.done:
				c.Subscribers.remove(sub)
			case sub.C <- &WorkloadUpdate{Entries: subEntries, Bundle: bundle}:
			}
		}
	}()
}

func (c *cacheImpl) DeleteEntry(regEntry *common.RegistrationEntry) (deleted bool) {
	c.m.Lock()
	defer c.m.Unlock()

	var subs []*Subscriber
	if entry, found := c.cache[regEntry.EntryId]; found {
		subs = c.Subscribers.Get(entry.RegistrationEntry.Selectors)
		delete(c.cache, regEntry.EntryId)
		deleted = true
		c.notifySubscribers(subs)
	}

	return
}

func (c *cacheImpl) IsEmpty() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return len(c.cache) == 0
}

func subscriberEntries(sub *Subscriber, entries []*Entry) (subentries []*Entry) {
	for _, e := range entries {
		regEntrySelectors := selector.NewSetFromRaw(e.RegistrationEntry.Selectors)
		if selector.NewSetFromRaw(sub.sel).IncludesSet(regEntrySelectors) {
			subentries = append(subentries, e)
		}
	}
	return
}
