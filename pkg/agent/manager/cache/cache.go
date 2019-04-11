package cache

import (
	"crypto/ecdsa"
	"crypto/x509"
	"sort"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/proto/spire/common"
)

type Selectors []*common.Selector
type Bundle = bundleutil.Bundle

// Entry holds the data of a single cache entry
type Entry struct {
	RegistrationEntry *common.RegistrationEntry
	SVID              []*x509.Certificate
	PrivateKey        *ecdsa.PrivateKey
}

// WorkloadUpdate is used to convey workload information to cache subscribers
type WorkloadUpdate struct {
	Entries          []Entry
	Bundle           *bundleutil.Bundle
	FederatedBundles map[string]*bundleutil.Bundle
}

// CacheUpdate holds information for an update to the cache.
type CacheUpdate struct {
	// Bundles is a set of ALL trust bundles available to the agent, keyed by
	// trust domain id.
	Bundles map[string]*bundleutil.Bundle

	// RegistrationEntries is a set ALL registration entries available to the
	// agent, keyed by registration entry id.
	RegistrationEntries map[string]*common.RegistrationEntry

	// X509SVIDs is a set of updated X509-SVIDs that should be merged into
	// the cache, keyed by registration entry id.
	X509SVIDs map[string]*X509SVID
}

// X509SVID holds onto the SVID certificate chain and private key.
type X509SVID struct {
	Chain      []*x509.Certificate
	PrivateKey *ecdsa.PrivateKey
}

// Cache caches registration entries, signed X509-SVIDs for those entries,
// bundles, and JWT SVIDs for the agent. It allows subscriptions by (workload)
// selector sets and notifies subscribers when:
//
// 1) a registration entry related to the selectors:
//   * is modified
//   * has a new X509-SVID signed for it
//   * federates with a federated bundle that is updated
// 2) the trust bundle for the agent trust domain is updated
//
// When notified, the subscriber is given a WorkloadUpdate containing
//.registration entries with their corresponding SVIDs and private keys along
// with all related trust bundles.
//
// The cache does this efficiently by building an index for each unique
// selector it encounters. Each selector index tracks the subscribers (i.e
// workloads) and registration entries that have that selector.
//
// When registration entries are added/updated/removed, the set of revelant
// selectors are gathered and the indexes for those selectors are combed for
// all relevant subscribers.
//
// For each relevant subscriber, the selector index for each selector of the
// subscriber is combed for registration whose selectors are a subset of the
// subscriber selector set. Those entries are added to the workload update
// returned to the subscriber.
//
// NOTE: The cache is intended to be able to handle thousands of workload
// subscriptions, which can involve thousands of certificates, keys, bundles,
// and registration entries, etc. The selector index itself is intended to be
// scalable, but the objects themselves can take a considerable amount of
// memory. For maximal safety, the objects should be cloned both coming in and
// leaving the cache. However, during global updates (e.g. trust bundle is
// updated for the agent trust domain) in particular, cloning all of the
// revelant objects for each subscriber causes HUGE amounts of memory pressure
// which adds non-trivial amounts of latency and causes a giant memory spike
// that could OOM the agent on smaller VMs. For this reason, the cache is
// presumed to own ALL data passing in and out of the cache. Produces MUST NOT
// consumers MUST NOT mutate the data.
type Cache struct {
	*BundleCache
	*JWTSVIDCache

	log           logrus.FieldLogger
	trustDomainID string

	mu sync.RWMutex

	// cache entries for registration entries, keyed by registration entry ID
	entries map[string]*cacheEntry

	// selector indices, keyed by a selector key
	selectors map[selector]*selectorIndex

	// trust bundles, keyed by trust domain id (i.e. "spiffe://domain.test")
	bundles map[string]*bundleutil.Bundle
}

func New(log logrus.FieldLogger, trustDomainID string, bundle *Bundle) *Cache {
	return &Cache{
		BundleCache:  NewBundleCache(trustDomainID, bundle),
		JWTSVIDCache: NewJWTSVIDCache(),

		log:           log,
		trustDomainID: trustDomainID,
		entries:       make(map[string]*cacheEntry),
		selectors:     make(map[selector]*selectorIndex),
		bundles: map[string]*bundleutil.Bundle{
			trustDomainID: bundle,
		},
	}
}

// Entries is only used by manager tests.
// TODO: We should remove this and find a better way.
func (c *Cache) Entries() []Entry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]Entry, 0, len(c.entries))
	for _, entry := range c.entries {
		if entry.svid == nil {
			continue
		}
		out = append(out, makeEntry(entry))
	}
	sortEntries(out)
	return out
}

func (c *Cache) MatchingEntries(selectors []*common.Selector) []Entry {
	set := allocSelectorSet(selectors...)
	defer freeSelectorSet(set)

	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.matchingEntries(set)
}

func (c *Cache) FetchWorkloadUpdate(selectors []*common.Selector) *WorkloadUpdate {
	set := allocSelectorSet(selectors...)
	defer freeSelectorSet(set)

	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.buildWorkloadUpdate(set)
}

func (c *Cache) SubscribeToWorkloadUpdates(selectors []*common.Selector) Subscriber {
	c.mu.Lock()
	defer c.mu.Unlock()

	sub := newSubscriber(c, selectors)
	for s := range sub.set {
		c.addSelectorIndexSub(s, sub)
	}
	c.notify(sub)
	return sub
}

func (c *Cache) Update(update *CacheUpdate, checkSVID func(*common.RegistrationEntry, *X509SVID)) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// remove bundles that no longer exist and update bundle with changes,
	// populating a "changed" set that we can check when processing
	// registration entries to know if they need to spawn a notification.
	// never remove the bundle for the trust domain.
	bundleRemoved := false
	for id := range c.bundles {
		if _, ok := update.Bundles[id]; id != c.trustDomainID && !ok {
			bundleRemoved = true
			// bundle no longer exists.
			c.log.WithField("id", id).Debug("Bundle removed")
			delete(c.bundles, id)
		}
	}
	bundleChanged := make(map[string]bool)
	for id, bundle := range update.Bundles {
		existing, ok := c.bundles[id]
		if !(ok && existing.EqualTo(bundle)) {
			if !ok {
				c.log.WithField("id", id).Debug("Bundle added")
			} else {
				c.log.WithField("id", id).Debug("Bundle updated")
			}
			bundleChanged[id] = true
			c.bundles[id] = bundle
		}
	}
	trustDomainBundleChanged := bundleChanged[c.trustDomainID]

	// the set of selectors to notify against.
	set := allocSelectorSet()
	defer freeSelectorSet(set)

	// remove registration entries that no longer exist
	for id, entry := range c.entries {
		if _, ok := update.RegistrationEntries[id]; !ok {
			c.log.WithFields(logrus.Fields{
				"entry_id":  id,
				"spiffe_id": entry.regEntry.SpiffeId,
			}).Debug("Entry removed")
			c.diffSelectors(set, entry, entry.regEntry, nil)
			delete(c.entries, id)
		}
	}

	// add/update registration entries
	for _, regEntry := range update.RegistrationEntries {
		entry, entryExists := c.entries[regEntry.EntryId]
		if !entryExists {
			entry = newCacheEntry()
			c.entries[regEntry.EntryId] = entry
		}

		selAdd, selRem := c.diffSelectors(set, entry, entry.regEntry, regEntry)
		fedAdd, fedRem := c.diffFederatesWith(entry.regEntry, regEntry)

		entry.regEntry = regEntry

		// Now figure out if something related to the entry has changed so
		// interested subscribers can be notified.
		federatedBundlesChanged := fedAdd > 0 || fedRem > 0
		for _, id := range regEntry.FederatesWith {
			if bundleChanged[id] {
				federatedBundlesChanged = true
				break
			}
		}

		// Check if the X509-SVID was updated for this entry
		svid, svidUpdated := update.X509SVIDs[regEntry.EntryId]
		if svidUpdated {
			entry.svid = svid
		}

		metaUpdated := federatedBundlesChanged || svidUpdated

		// something related to this entry changed outside of the selectors.
		// make sure subscribers are notified.
		if metaUpdated {
			set.Merge(regEntry.Selectors...)
		}

		// Invoke the svid checker callback for this entry
		if checkSVID != nil {
			checkSVID(regEntry, entry.svid)
		}

		if selAdd > 0 || selRem > 0 || fedAdd > 0 || fedRem > 0 || svidUpdated {
			log := c.log.WithFields(logrus.Fields{
				"entry_id":  regEntry.EntryId,
				"spiffe_id": regEntry.SpiffeId,
			})
			if svidUpdated {
				log = log.WithField("svid_updated", svidUpdated)
			}
			if selAdd > 0 {
				log = log.WithField("sel_add", selAdd)
			}
			if selRem > 0 {
				log = log.WithField("sel_rem", selRem)
			}
			if fedAdd > 0 {
				log = log.WithField("fed_add", fedAdd)
			}
			if fedRem > 0 {
				log = log.WithField("fed_rem", fedRem)
			}
			if entryExists {
				log.Debug("Entry updated")
			} else {
				log.Debug("Entry created")
			}
		}
	}

	if bundleRemoved || len(bundleChanged) > 0 {
		c.BundleCache.Update(c.bundles)
	}

	if trustDomainBundleChanged {
		c.notifyAll()
	} else {
		c.notifySet(set)
	}
}

func (c *Cache) diffSelectors(set selectorSet, entry *cacheEntry, oldRegEntry, newRegEntry *common.RegistrationEntry) (added, removed int) {
	var selAdd selectorSet
	var selRem selectorSet

	// make a set of all the selectors being added
	if newRegEntry != nil {
		selAdd = allocSelectorSet(newRegEntry.Selectors...)
		defer freeSelectorSet(selAdd)
	}

	// make a set of all the selectors that are being removed
	if oldRegEntry != nil {
		selRem = allocSelectorSet()
		defer freeSelectorSet(selRem)
		for _, selector := range oldRegEntry.Selectors {
			s := makeSelector(selector)
			if _, ok := selAdd[s]; ok {
				// selector already exists in entry
				delete(selAdd, s)
			} else {
				// selector has been removed from entry
				selRem[s] = struct{}{}
			}
		}
	}

	// add entry to each selector being added and aggregate the selector
	// for notification
	for selector := range selAdd {
		c.addSelectorIndexEntry(selector, entry)
	}
	set.MergeSet(selAdd)

	// drop entry from each selector being removed and aggregate the selector
	// for notification
	for selector := range selRem {
		c.delSelectorIndexEntry(selector, entry)
	}
	set.MergeSet(selRem)

	return len(selAdd), len(selRem)
}

func (c *Cache) unsubscribe(sub *subscriber) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for selector := range sub.set {
		c.delSelectorIndexSub(selector, sub)
	}
}

func (c *Cache) diffFederatesWith(oldRegEntry, newRegEntry *common.RegistrationEntry) (added, removed int) {
	var fedAdd stringSet
	var fedRem stringSet

	// make a set of all the selectors being added
	if newRegEntry != nil {
		fedAdd = allocStringSet(newRegEntry.FederatesWith...)
		defer freeStringSet(fedAdd)
	}

	// make a set of all the selectors that are being removed
	if oldRegEntry != nil {
		fedRem = allocStringSet()
		defer freeStringSet(fedRem)
		for _, id := range oldRegEntry.FederatesWith {
			if _, ok := fedAdd[id]; ok {
				// bundle already exists in entry
				delete(fedAdd, id)
			} else {
				// bundle has been removed from entry
				fedRem[id] = struct{}{}
			}
		}
	}

	return len(fedAdd), len(fedRem)
}

func (c *Cache) addSelectorIndexEntry(s selector, entry *cacheEntry) {
	index := c.getSelectorIndex(s)
	index.entries[entry] = struct{}{}
}

func (c *Cache) delSelectorIndexEntry(s selector, entry *cacheEntry) {
	index, ok := c.selectors[s]
	if ok {
		delete(index.entries, entry)
		if index.isEmpty() {
			delete(c.selectors, s)
		}
	}
}

func (c *Cache) addSelectorIndexSub(s selector, sub *subscriber) {
	index := c.getSelectorIndex(s)
	index.subs[sub] = struct{}{}
}

func (c *Cache) delSelectorIndexSub(s selector, sub *subscriber) {
	index, ok := c.selectors[s]
	if ok {
		delete(index.subs, sub)
		if index.isEmpty() {
			delete(c.selectors, s)
		}
	}
}

func (c *Cache) notifyAll() {
	subs := c.allSubscribers()
	defer freeSubscriberSet(subs)
	for sub := range subs {
		c.notify(sub)
	}
}

func (c *Cache) notifySet(set selectorSet) {
	subs := c.getSubscribers(set)
	defer freeSubscriberSet(subs)
	for sub := range subs {
		c.notify(sub)
	}
}

func (c *Cache) notify(sub *subscriber) {
	update := c.buildWorkloadUpdate(sub.set)
	sub.notify(update)
}

func (c *Cache) allSubscribers() subscriberSet {
	subs := allocSubscriberSet()
	for _, index := range c.selectors {
		for sub := range index.subs {
			subs[sub] = struct{}{}
		}
	}
	return subs
}

func (c *Cache) getSubscribers(set selectorSet) subscriberSet {
	subs := allocSubscriberSet()
	for s := range set {
		index := c.getSelectorIndex(s)
		for sub := range index.subs {
			subs[sub] = struct{}{}
		}
	}
	return subs
}

func (c *Cache) matchingEntries(set selectorSet) []Entry {
	entries := c.getEntriesForSelectors(set)
	defer freeEntriesSet(entries)

	if len(entries) == 0 {
		return nil
	}

	// return entries in ascdending "entry id" order to maintain a consistent
	// ordering.
	// TODO: figure out how to determine the "default" entry
	out := make([]Entry, 0, len(entries))
	for entry := range entries {
		out = append(out, makeEntry(entry))
	}
	sortEntries(out)
	return out
}

func (c *Cache) buildWorkloadUpdate(set selectorSet) *WorkloadUpdate {
	w := &WorkloadUpdate{
		Bundle:           c.bundles[c.trustDomainID],
		FederatedBundles: make(map[string]*bundleutil.Bundle),
		Entries:          c.matchingEntries(set),
	}

	// add in the bundles
	for _, entry := range w.Entries {
		for _, federatesWith := range entry.RegistrationEntry.FederatesWith {
			if federatedBundle := c.bundles[federatesWith]; federatedBundle != nil {
				w.FederatedBundles[federatesWith] = federatedBundle
			}
		}
	}

	return w
}

func (c *Cache) getEntriesForSelectors(set selectorSet) entriesSet {
	// Build and dedup a list of candidate entries. Ignore those without an
	// SVID but otherwise don't check for selector set inclusion yet, since
	// that is a more expensive operation and we could easily have duplicate
	// entries to check.
	entries := allocEntriesSet()
	for selector := range set {
		index := c.getSelectorIndex(selector)
		for entry := range index.entries {
			if entry.svid == nil {
				continue
			}
			entries[entry] = struct{}{}
		}
	}

	// Filter the entries by those inside the selector set
	for entry := range entries {
		for _, s := range entry.regEntry.Selectors {
			if !set.In(s) {
				delete(entries, entry)
			}
		}
	}
	return entries
}

// getSelectorIndex gets a selector index entry for the selector. If one
// doesn't exist, it is created.
func (c *Cache) getSelectorIndex(s selector) *selectorIndex {
	index, ok := c.selectors[s]
	if !ok {
		index = newSelectorIndex()
		c.selectors[s] = index
	}
	return index
}

type cacheEntry struct {
	regEntry *common.RegistrationEntry
	svid     *X509SVID
	subs     map[*subscriber]struct{}
}

func newCacheEntry() *cacheEntry {
	return &cacheEntry{
		subs: make(map[*subscriber]struct{}),
	}
}

type selectorIndex struct {
	// subscriptions related to this selector
	subs map[*subscriber]struct{}

	// cache entries related to this selector
	entries map[*cacheEntry]struct{}
}

func (x *selectorIndex) isEmpty() bool {
	return len(x.subs) == 0 && len(x.entries) == 0
}

func newSelectorIndex() *selectorIndex {
	return &selectorIndex{
		subs:    make(map[*subscriber]struct{}),
		entries: make(map[*cacheEntry]struct{}),
	}
}

func sortEntries(entries []Entry) {
	sort.Slice(entries, func(a, b int) bool {
		return entries[a].RegistrationEntry.EntryId < entries[b].RegistrationEntry.EntryId
	})
}

func makeEntry(entry *cacheEntry) Entry {
	return Entry{
		RegistrationEntry: entry.regEntry,
		SVID:              entry.svid.Chain,
		PrivateKey:        entry.svid.PrivateKey,
	}
}
