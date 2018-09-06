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
}

// Wraps an observer stream to provide a type safe interface
type BundleStream struct {
	stream observer.Stream
}

func NewBundleStream(stream observer.Stream) *BundleStream {
	return &BundleStream{
		stream: stream,
	}
}

// Value returns the current value for this stream.
func (b *BundleStream) Value() map[string][]*x509.Certificate {
	value, _ := b.stream.Value().(map[string][]*x509.Certificate)
	return value
}

// Changes returns the channel that is closed when a new value is available.
func (b *BundleStream) Changes() chan struct{} {
	return b.stream.Changes()
}

// Next advances this stream to the next state.
// You should never call this unless Changes channel is closed.
func (b *BundleStream) Next() map[string][]*x509.Certificate {
	value, _ := b.stream.Next().(map[string][]*x509.Certificate)
	return value
}

// HasNext checks whether there is a new value available.
func (b *BundleStream) HasNext() bool {
	return b.stream.HasNext()
}

// WaitNext waits for Changes to be closed, advances the stream and returns
// the current value.
func (b *BundleStream) WaitNext() map[string][]*x509.Certificate {
	value, _ := b.stream.WaitNext().(map[string][]*x509.Certificate)
	return value
}

// Clone creates a new independent stream from this one but sharing the same
// Property. Updates to the property will be reflected in both streams but
// they may have different values depending on when they advance the stream
// with Next.
func (b *BundleStream) Clone() *BundleStream {
	return &BundleStream{
		stream: b.stream.Clone(),
	}
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
	// Registers and returns a Subscriber, and then sends latest WorkloadUpdate on its channel
	Subscribe(selectors Selectors) Subscriber
	// Set the bundles
	SetBundles(map[string][]*x509.Certificate)
	// Retrieve the bundle for the trust domain
	Bundle() []*x509.Certificate
	// SubscribeToBundleChanges returns a bundle stream. Each
	// time bundles are updated, a new bundle mapping is streamed.
	SubscribeToBundleChanges() *BundleStream
}

type cacheImpl struct {
	// Map keyed by RegistrationEntry.EntryId holding Entry instances.
	cache       map[string]*Entry
	log         logrus.FieldLogger
	m           sync.Mutex
	subscribers *subscribers
	trustDomain string
	bundles     observer.Property
	notifyMutex sync.Mutex
}

// New creates a new Cache.
func New(log logrus.FieldLogger, trustDomain string, bundle []*x509.Certificate) *cacheImpl {
	bundles := map[string][]*x509.Certificate{
		trustDomain: bundle,
	}
	return &cacheImpl{
		cache:       make(map[string]*Entry),
		log:         log.WithField("subsystem_name", "cache"),
		trustDomain: trustDomain,
		bundles:     observer.NewProperty(bundles),
		subscribers: NewSubscribers(),
	}
}

func (c *cacheImpl) SetBundles(newBundles map[string][]*x509.Certificate) {
	// SetBundles() and Bundle()/Bundles() can be called concurrently since
	// the "property" is atomic. Before the following code can merge in changes
	// it needs to make a copy of the map to mutate so it doesn't modify
	// the bundle map out from underneath readers. SetBundles() is not intended
	// to be called by more than one goroutine at a time.

	// copy the map
	bundles := make(map[string][]*x509.Certificate)
	for k, v := range c.Bundles() {
		bundles[k] = v
	}

	// merge in changes
	changed := false
	for id, newBundle := range newBundles {
		bundle, ok := bundles[id]
		if !ok || !certsEqual(bundle, newBundle) {
			bundles[id] = newBundle
			changed = true
		}
	}

	// notify subscribers
	// TODO: be more selective about which subscribers get updated to reduce
	// unnecessary workload updates.
	if changed {
		c.bundles.Update(bundles)
		subs := c.subscribers.getAll()
		c.notifySubscribers(subs)
	}
}

func (c *cacheImpl) Bundle() []*x509.Certificate {
	return c.Bundles()[c.trustDomain]
}

func (c *cacheImpl) Bundles() map[string][]*x509.Certificate {
	return c.bundles.Value().(map[string][]*x509.Certificate)
}

func (c *cacheImpl) SubscribeToBundleChanges() *BundleStream {
	return NewBundleStream(c.bundles.Observe())
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
	bundles := c.Bundles()

	bundle := bundles[c.trustDomain]

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

		federatedBundles := make(map[string][]*x509.Certificate)
		for _, subEntry := range subEntries {
			for _, federatesWith := range subEntry.RegistrationEntry.FederatesWith {
				federatedBundle := bundles[federatesWith]
				if len(federatedBundle) > 0 {
					federatedBundles[federatesWith] = federatedBundle
				}
			}
		}

		update := &WorkloadUpdate{
			Entries:          subEntries,
			Bundle:           bundle,
			FederatedBundles: federatedBundles,
		}

		sub.c <- update
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

func subscriberEntries(sub *subscriber, entries []*Entry) (subentries []*Entry) {
	for _, e := range entries {
		regEntrySelectors := selector.NewSetFromRaw(e.RegistrationEntry.Selectors)
		if selector.NewSetFromRaw(sub.sel).IncludesSet(regEntrySelectors) {
			subentries = append(subentries, e)
		}
	}
	return
}

func certsEqual(a, b []*x509.Certificate) bool {
	if len(a) != len(b) {
		return false
	}

	for i, cert := range a {
		if !cert.Equal(b[i]) {
			return false
		}
	}

	return true
}
