package cache

import (
	"crypto/ecdsa"
	"crypto/x509"
	"sync"

	"github.com/imkira/go-observer"
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
	// Registers and returns a Subscriber, and then sends latest WorkloadUpdate on its channel
	Subscribe(selectors Selectors) Subscriber
	// Set the bundle
	SetBundle([]*x509.Certificate)
	// Retrieve the bundle
	Bundle() []*x509.Certificate
	// SubscribeToBundleChanges returns a new observer.Stream of []*x509.Certificate instances. Each
	// time the bundle is updated, a new instance is streamed.
	SubscribeToBundleChanges() observer.Stream
}

type cacheImpl struct {
	// Map keyed by RegistrationEntry.EntryId holding Entry instances.
	cache       map[string]*Entry
	log         logrus.FieldLogger
	m           sync.Mutex
	subscribers *subscribers
	bundle      observer.Property
	notifyMutex sync.Mutex
}

// New creates a new Cache.
func New(log logrus.FieldLogger, bundle []*x509.Certificate) *cacheImpl {
	return &cacheImpl{
		cache:       make(map[string]*Entry),
		log:         log.WithField("subsystem_name", "cache"),
		bundle:      observer.NewProperty(bundle),
		subscribers: NewSubscribers(),
	}
}

func (c *cacheImpl) SetBundle(bundle []*x509.Certificate) {
	c.bundle.Update(bundle)
	subs := c.subscribers.getAll()
	c.notifySubscribers(subs)
}

func (c *cacheImpl) Bundle() []*x509.Certificate {
	return c.bundle.Value().([]*x509.Certificate)
}

func (c *cacheImpl) SubscribeToBundleChanges() observer.Stream {
	return c.bundle.Observe()
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

func (c *cacheImpl) Subscribe(selectors Selectors) Subscriber {
	// creates a subscriber
	// adds it to the manager
	// returns the added subscriber
	sub, err := NewSubscriber(selectors)
	if err != nil {
		c.log.Error(err)
	}
	c.subscribers.add(sub)
	c.notifySubscribers([]*subscriber{sub})
	return sub
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

	subs := c.subscribers.get(entry.RegistrationEntry.Selectors)
	c.notifySubscribers(subs)
}

func (c *cacheImpl) notifySubscribers(subs []*subscriber) {
	if subs == nil {
		return
	}

	c.notifyMutex.Lock()
	defer c.notifyMutex.Unlock()

	entries := c.Entries()
	bundle := c.Bundle()
	for _, sub := range subs {
		sub.m.Lock()
		// If subscriber is not active any more, remove it.
		if !sub.active {
			c.subscribers.remove(sub)
			sub.m.Unlock()
			continue
		}

		select {
		case <-sub.c:
			// Discard current update if there is one.
		default:
			// To prevent blocking if there is no update available.
		}

		subEntries := subscriberEntries(sub, entries)
		sub.c <- &WorkloadUpdate{Entries: subEntries, Bundle: bundle}
		sub.m.Unlock()
	}
}

func (c *cacheImpl) DeleteEntry(regEntry *common.RegistrationEntry) (deleted bool) {
	c.m.Lock()
	var subs []*subscriber
	if entry, found := c.cache[regEntry.EntryId]; found {
		subs = c.subscribers.get(entry.RegistrationEntry.Selectors)
		delete(c.cache, regEntry.EntryId)
		deleted = true
	}
	c.m.Unlock()

	if deleted {
		c.notifySubscribers(subs)
	}
	return
}

func (c *cacheImpl) IsEmpty() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return len(c.cache) == 0
}

func subscriberEntries(sub *subscriber, entries []*Entry) (subentries []*Entry) {
	for _, e := range entries {
		regEntrySelectors := selector.NewSetFromRaw(e.RegistrationEntry.Selectors)
		if selector.NewSetFromRaw(sub.sel).IncludesSet(regEntrySelectors) {
			subentries = append(subentries, e)
		}
	}
	return
}
