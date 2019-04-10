package cache

import (
	"crypto/ecdsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"io"
	"sort"
	"sync"

	"github.com/imkira/go-observer"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/proto/common"
)

type Selectors []*common.Selector
type Bundle = bundleutil.Bundle

// Entry holds the data of a single cache entry.
type Entry struct {
	RegistrationEntry *common.RegistrationEntry
	SVID              []*x509.Certificate
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
func (b *BundleStream) Value() map[string]*Bundle {
	value, _ := b.stream.Value().(map[string]*Bundle)
	return value
}

// Changes returns the channel that is closed when a new value is available.
func (b *BundleStream) Changes() chan struct{} {
	return b.stream.Changes()
}

// Next advances this stream to the next state.
// You should never call this unless Changes channel is closed.
func (b *BundleStream) Next() map[string]*Bundle {
	value, _ := b.stream.Next().(map[string]*Bundle)
	return value
}

// HasNext checks whether there is a new value available.
func (b *BundleStream) HasNext() bool {
	return b.stream.HasNext()
}

// WaitNext waits for Changes to be closed, advances the stream and returns
// the current value.
func (b *BundleStream) WaitNext() map[string]*Bundle {
	value, _ := b.stream.WaitNext().(map[string]*Bundle)
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
	// FetchEntry gets the cache entry for the specified registration entry id
	FetchEntry(entryId string) *Entry
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
	SetBundles(map[string]*Bundle)
	// Retrieve the bundle for the trust domain
	Bundle() *Bundle
	// SubscribeToBundleChanges returns a bundle stream. Each
	// time bundles are updated, a new bundle mapping is streamed.
	SubscribeToBundleChanges() *BundleStream
	// FetchWorkloadUpdates gets the latest workload update for the selectors
	FetchWorkloadUpdate(selectors Selectors) *WorkloadUpdate

	// GetJWTSVID retrieves a cached JWT SVID based on the subject and
	// intended audience.
	GetJWTSVID(spiffeID string, audience []string) (*client.JWTSVID, bool)
	// SetJWTSVID caches a JWT SVID based on the subject and intended audience.
	SetJWTSVID(spiffeID string, audience []string, svid *client.JWTSVID)
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
	jwtSVIDS    map[string]*client.JWTSVID
}

// New creates a new Cache.
func New(log logrus.FieldLogger, trustDomain string, bundle *Bundle) *cacheImpl {
	bundles := map[string]*Bundle{
		trustDomain: bundle,
	}
	return &cacheImpl{
		cache:       make(map[string]*Entry),
		log:         log.WithField("subsystem_name", "cache"),
		trustDomain: trustDomain,
		bundles:     observer.NewProperty(bundles),
		subscribers: newSubscribers(),
		jwtSVIDS:    make(map[string]*client.JWTSVID),
	}
}

func (c *cacheImpl) SetBundles(newBundles map[string]*Bundle) {
	// SetBundles() and Bundle()/Bundles() can be called concurrently since
	// the "property" is atomic. Before the following code can merge in changes
	// it needs to make a copy of the map to mutate so it doesn't modify
	// the bundle map out from underneath readers. SetBundles() is not intended
	// to be called by more than one goroutine at a time.

	// copy the map
	bundles := make(map[string]*Bundle)
	for k, v := range c.Bundles() {
		bundles[k] = v
	}

	// merge in changes
	changed := false
	for id, newBundle := range newBundles {
		bundle := bundles[id]
		if bundle == nil || !bundle.EqualTo(newBundle) {
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
		c.notifySubscribers(subs...)
	}
}

func (c *cacheImpl) Bundle() *Bundle {
	return c.Bundles()[c.trustDomain]
}

func (c *cacheImpl) Bundles() map[string]*Bundle {
	return c.bundles.Value().(map[string]*Bundle)
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
	sub := c.subscribers.add(selectors)
	c.notifySubscribers(sub)
	return sub
}

func (c *cacheImpl) FetchEntry(entryID string) *Entry {
	c.m.Lock()
	defer c.m.Unlock()
	if entry, found := c.cache[entryID]; found {
		return entry
	}
	return nil
}

func (c *cacheImpl) SetEntry(entry *Entry) {
	c.m.Lock()
	c.cache[entry.RegistrationEntry.EntryId] = entry
	c.m.Unlock()

	subs := c.subscribers.get(entry.RegistrationEntry.Selectors)
	c.notifySubscribers(subs...)
}

func (c *cacheImpl) notifySubscribers(subs ...*subscriber) {
	if subs == nil {
		return
	}

	c.notifyMutex.Lock()
	defer c.notifyMutex.Unlock()

	entries := c.Entries()
	bundles := c.Bundles()

	for _, sub := range subs {
		subEntries := subscriberEntries(sub, entries)
		update := c.makeWorkloadUpdate(subEntries, bundles)
		sub.sendUpdate(update)
	}
}

func (c *cacheImpl) makeWorkloadUpdate(entries []*Entry, bundles map[string]*Bundle) *WorkloadUpdate {
	bundle := bundles[c.trustDomain]

	federatedBundles := make(map[string]*Bundle)
	for _, entry := range entries {
		for _, federatesWith := range entry.RegistrationEntry.FederatesWith {
			if federatedBundle := bundles[federatesWith]; federatedBundle != nil {
				federatedBundles[federatesWith] = federatedBundle
			}
		}
	}

	return &WorkloadUpdate{
		Entries:          entries,
		Bundle:           bundle,
		FederatedBundles: federatedBundles,
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
		c.notifySubscribers(subs...)
	}
	return
}

func (c *cacheImpl) FetchWorkloadUpdate(selectors Selectors) *WorkloadUpdate {
	entries := c.Entries()
	bundles := c.Bundles()

	return c.makeWorkloadUpdate(selectorsEntries(selector.NewSetFromRaw(selectors), entries), bundles)
}

func (c *cacheImpl) GetJWTSVID(spiffeID string, audience []string) (*client.JWTSVID, bool) {
	key := keyFromJWTSpiffeIDAndAudience(spiffeID, audience)
	c.m.Lock()
	defer c.m.Unlock()
	svid, ok := c.jwtSVIDS[key]
	return svid, ok
}

func (c *cacheImpl) SetJWTSVID(spiffeID string, audience []string, svid *client.JWTSVID) {
	key := keyFromJWTSpiffeIDAndAudience(spiffeID, audience)

	c.m.Lock()
	defer c.m.Unlock()
	c.jwtSVIDS[key] = svid
}

func subscriberEntries(sub *subscriber, entries []*Entry) (subentries []*Entry) {
	return selectorsEntries(sub.selSet, entries)
}

func selectorsEntries(selectors selector.Set, entries []*Entry) (subentries []*Entry) {
	for _, e := range entries {
		regEntrySelectors := selector.NewSetFromRaw(e.RegistrationEntry.Selectors)
		if selectors.IncludesSet(regEntrySelectors) {
			subentries = append(subentries, e)
		}
	}
	return subentries
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

func keyFromJWTSpiffeIDAndAudience(spiffeID string, audience []string) string {
	h := sha1.New()

	// duplicate and sort the audience slice before sorting
	audience = append([]string(nil), audience...)
	sort.Strings(audience)

	io.WriteString(h, spiffeID)
	for _, a := range audience {
		io.WriteString(h, a)
	}

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
