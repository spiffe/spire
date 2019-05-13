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

// Identity holds the data for a single workload identity
type Identity struct {
	Entry      *common.RegistrationEntry
	SVID       []*x509.Certificate
	PrivateKey *ecdsa.PrivateKey
}

// WorkloadUpdate is used to convey workload information to cache subscribers
type WorkloadUpdate struct {
	Identities       []Identity
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

// Cache caches each registration entry, signed X509-SVIDs for those entries,
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
// related identities and trust bundles.
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
// subscriber selector set. Identities for those entries are added to the
// workload update returned to the subscriber.
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
// presumed to own ALL data passing in and out of the cache. Producers and
// consumers MUST NOT mutate the data.
type Cache struct {
	*BundleCache
	*JWTSVIDCache

	log           logrus.FieldLogger
	trustDomainID string

	mu sync.RWMutex

	// records holds the records for registration entries, keyed by registration entry ID
	records map[string]*cacheRecord

	// selectors holds the selector indices, keyed by a selector key
	selectors map[selector]*selectorIndex

	// bundles holds the trust bundles, keyed by trust domain id (i.e. "spiffe://domain.test")
	bundles map[string]*bundleutil.Bundle
}

func New(log logrus.FieldLogger, trustDomainID string, bundle *Bundle) *Cache {
	return &Cache{
		BundleCache:  NewBundleCache(trustDomainID, bundle),
		JWTSVIDCache: NewJWTSVIDCache(),

		log:           log,
		trustDomainID: trustDomainID,
		records:       make(map[string]*cacheRecord),
		selectors:     make(map[selector]*selectorIndex),
		bundles: map[string]*bundleutil.Bundle{
			trustDomainID: bundle,
		},
	}
}

// Identities is only used by manager tests
// TODO: We should remove this and find a better way
func (c *Cache) Identities() []Identity {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]Identity, 0, len(c.records))
	for _, record := range c.records {
		if record.svid == nil {
			// The record does not have an SVID yet and should not be returned
			// from the cache.
			continue
		}
		out = append(out, makeIdentity(record))
	}
	sortIdentities(out)
	return out
}

func (c *Cache) MatchingIdentities(selectors []*common.Selector) []Identity {
	set, setDone := allocSelectorSet(selectors...)
	defer setDone()

	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.matchingIdentities(set)
}

func (c *Cache) FetchWorkloadUpdate(selectors []*common.Selector) *WorkloadUpdate {
	set, setDone := allocSelectorSet(selectors...)
	defer setDone()

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

	// Remove bundles that no longer exist. The bundle for the agent trust
	// domain should NOT be removed even if not present (which should only be
	// the case if there is a bug on the server) since it is necessary to
	// authenticate the server.
	bundleRemoved := false
	for id := range c.bundles {
		if _, ok := update.Bundles[id]; !ok && id != c.trustDomainID {
			bundleRemoved = true
			// bundle no longer exists.
			c.log.WithField("id", id).Debug("Bundle removed")
			delete(c.bundles, id)
		}
	}

	// Update bundles with changes, populating a "changed" set that we can
	// check when processing registration entries to know if they need to spawn
	// a notification.
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

	// Allocate a set of selectors that
	notifySet, selSetDone := allocSelectorSet()
	defer selSetDone()

	// Allocate sets from the pool to track changes to selectors and
	// federatesWith declarations. These sets must be cleared after EACH use
	// and returned to their respective pools when done processing the
	// updates.
	selAdd, selAddDone := allocSelectorSet()
	defer selAddDone()
	selRem, selRemDone := allocSelectorSet()
	defer selRemDone()
	fedAdd, fedAddDone := allocStringSet()
	defer fedAddDone()
	fedRem, fedRemDone := allocStringSet()
	defer fedRemDone()

	// Remove records for registration entries that no longer exist
	for id, record := range c.records {
		if _, ok := update.RegistrationEntries[id]; !ok {
			c.log.WithFields(logrus.Fields{
				"entry_id":  id,
				"spiffe_id": record.entry.SpiffeId,
			}).Debug("Entry removed")

			// built a set of selectors for the record being removed, drop the
			// record for each selector index, and add the entry selectors to
			// the notify set.
			clearSelectorSet(selRem)
			selRem.Merge(record.entry.Selectors...)
			c.delSelectorIndicesRecord(selRem, record)
			notifySet.MergeSet(selRem)
			delete(c.records, id)
		}
	}

	// Add/update records for registration entries in the update
	for _, newEntry := range update.RegistrationEntries {
		clearSelectorSet(selAdd)
		clearSelectorSet(selRem)
		clearStringSet(fedAdd)
		clearStringSet(fedRem)

		record, existingEntry := c.updateOrCreateRecord(newEntry)

		// Calculate the difference in selectors, add/remove the record
		// from impacted selector indices, and add the selector diff to the
		// notify set.
		c.diffSelectors(existingEntry, newEntry, selAdd, selRem)
		c.addSelectorIndicesRecord(selAdd, record)
		c.delSelectorIndicesRecord(selRem, record)
		notifySet.MergeSet(selAdd)
		notifySet.MergeSet(selRem)

		// Determine if there were changes to FederatesWith declarations or
		// if any federated bundles related to the entry were updated.
		c.diffFederatesWith(existingEntry, newEntry, fedAdd, fedRem)
		federatedBundlesChanged := len(fedAdd) > 0 || len(fedRem) > 0
		if !federatedBundlesChanged {
			for _, id := range newEntry.FederatesWith {
				if bundleChanged[id] {
					federatedBundlesChanged = true
					break
				}
			}
		}

		// Determine if something related to this record changed outside of the
		// selectors and if so, make sure subscribers for all entry selectors
		// are notified.
		svid, svidUpdated := update.X509SVIDs[newEntry.EntryId]
		if svidUpdated {
			record.svid = svid
		}
		metaUpdated := federatedBundlesChanged || svidUpdated
		if metaUpdated {
			notifySet.Merge(newEntry.Selectors...)
		}

		// Invoke the svid checker callback for this record
		if checkSVID != nil {
			checkSVID(newEntry, record.svid)
		}

		// Log all the details of the update to the DEBUG log
		//
		// TODO: This is a bit verbose and could be trimmed in the future
		// when the cache implementation has stabilized.
		if len(selAdd) > 0 || len(selRem) > 0 || len(fedAdd) > 0 || len(fedRem) > 0 || svidUpdated {
			log := c.log.WithFields(logrus.Fields{
				"entry_id":  newEntry.EntryId,
				"spiffe_id": newEntry.SpiffeId,
			})
			if svidUpdated {
				log = log.WithField("svid_updated", svidUpdated)
			}
			if len(selAdd) > 0 {
				log = log.WithField("sel_add", len(selAdd))
			}
			if len(selRem) > 0 {
				log = log.WithField("sel_rem", len(selRem))
			}
			if len(fedAdd) > 0 {
				log = log.WithField("fed_add", len(fedAdd))
			}
			if len(fedRem) > 0 {
				log = log.WithField("fed_rem", len(fedRem))
			}
			if existingEntry != nil {
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
		c.notifyBySelectors(notifySet)
	}
}

func (c *Cache) updateOrCreateRecord(newEntry *common.RegistrationEntry) (*cacheRecord, *common.RegistrationEntry) {
	var existingEntry *common.RegistrationEntry
	record, recordExists := c.records[newEntry.EntryId]
	if !recordExists {
		record = newCacheRecord()
		c.records[newEntry.EntryId] = record
	} else {
		existingEntry = record.entry
	}
	record.entry = newEntry
	return record, existingEntry
}

func (c *Cache) diffSelectors(existingEntry, newEntry *common.RegistrationEntry, added, removed selectorSet) {
	// Make a set of all the selectors being added
	if newEntry != nil {
		added.Merge(newEntry.Selectors...)
	}

	// Make a set of all the selectors that are being removed
	if existingEntry != nil {
		for _, selector := range existingEntry.Selectors {
			s := makeSelector(selector)
			if _, ok := added[s]; ok {
				// selector already exists in entry
				delete(added, s)
			} else {
				// selector has been removed from entry
				removed[s] = struct{}{}
			}
		}
	}
}

func (c *Cache) diffFederatesWith(existingEntry, newEntry *common.RegistrationEntry, added, removed stringSet) {
	// Make a set of all the selectors being added
	if newEntry != nil {
		added.Merge(newEntry.FederatesWith...)
	}

	// Make a set of all the selectors that are being removed
	if existingEntry != nil {
		for _, id := range existingEntry.FederatesWith {
			if _, ok := added[id]; ok {
				// Bundle already exists in entry
				delete(added, id)
			} else {
				// Bundle has been removed from entry
				removed[id] = struct{}{}
			}
		}
	}
}

func (c *Cache) addSelectorIndicesRecord(selectors selectorSet, record *cacheRecord) {
	for selector := range selectors {
		c.addSelectorIndexRecord(selector, record)
	}
}

func (c *Cache) addSelectorIndexRecord(s selector, record *cacheRecord) {
	index := c.getSelectorIndex(s)
	index.records[record] = struct{}{}
}

func (c *Cache) delSelectorIndicesRecord(selectors selectorSet, record *cacheRecord) {
	for selector := range selectors {
		c.delSelectorIndexRecord(selector, record)
	}
}

// delSelectorIndexRecord removes the record from the selector index. If
// the selector index is empty afterwards, it is also removed.
func (c *Cache) delSelectorIndexRecord(s selector, record *cacheRecord) {
	index, ok := c.selectors[s]
	if ok {
		delete(index.records, record)
		if index.isEmpty() {
			delete(c.selectors, s)
		}
	}
}

func (c *Cache) addSelectorIndexSub(s selector, sub *subscriber) {
	index := c.getSelectorIndex(s)
	index.subs[sub] = struct{}{}
}

// delSelectorIndexSub removes the subscription from the selector index. If
// the selector index is empty afterwards, it is also removed.
func (c *Cache) delSelectorIndexSub(s selector, sub *subscriber) {
	index, ok := c.selectors[s]
	if ok {
		delete(index.subs, sub)
		if index.isEmpty() {
			delete(c.selectors, s)
		}
	}
}

func (c *Cache) unsubscribe(sub *subscriber) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for selector := range sub.set {
		c.delSelectorIndexSub(selector, sub)
	}
}

func (c *Cache) notifyAll() {
	subs, subsDone := c.allSubscribers()
	defer subsDone()
	for sub := range subs {
		c.notify(sub)
	}
}

func (c *Cache) notifyBySelectors(set selectorSet) {
	subs, subsDone := c.getSubscribers(set)
	defer subsDone()
	for sub := range subs {
		c.notify(sub)
	}
}

func (c *Cache) notify(sub *subscriber) {
	update := c.buildWorkloadUpdate(sub.set)
	sub.notify(update)
}

func (c *Cache) allSubscribers() (subscriberSet, func()) {
	subs, subsDone := allocSubscriberSet()
	for _, index := range c.selectors {
		for sub := range index.subs {
			subs[sub] = struct{}{}
		}
	}
	return subs, subsDone
}

func (c *Cache) getSubscribers(set selectorSet) (subscriberSet, func()) {
	subs, subsDone := allocSubscriberSet()
	for s := range set {
		index := c.getSelectorIndex(s)
		for sub := range index.subs {
			subs[sub] = struct{}{}
		}
	}
	return subs, subsDone
}

func (c *Cache) matchingIdentities(set selectorSet) []Identity {
	records, recordsDone := c.getRecordsForSelectors(set)
	defer recordsDone()

	if len(records) == 0 {
		return nil
	}

	// Return identities in ascending "entry id" order to maintain a consistent
	// ordering.
	// TODO: figure out how to determine the "default" identity
	out := make([]Identity, 0, len(records))
	for record := range records {
		out = append(out, makeIdentity(record))
	}
	sortIdentities(out)
	return out
}

func (c *Cache) buildWorkloadUpdate(set selectorSet) *WorkloadUpdate {
	w := &WorkloadUpdate{
		Bundle:           c.bundles[c.trustDomainID],
		FederatedBundles: make(map[string]*bundleutil.Bundle),
		Identities:       c.matchingIdentities(set),
	}

	// Add in the bundles the workload is federated with.
	for _, identity := range w.Identities {
		for _, federatesWith := range identity.Entry.FederatesWith {
			if federatedBundle := c.bundles[federatesWith]; federatedBundle != nil {
				w.FederatedBundles[federatesWith] = federatedBundle
			} else {
				c.log.WithFields(logrus.Fields{
					"entry_id":  identity.Entry.EntryId,
					"spiffe_id": identity.Entry.SpiffeId,
					"bundle_id": federatesWith,
				}).Warn("federated bundle contents missing")
			}
		}
	}

	return w
}

func (c *Cache) getRecordsForSelectors(set selectorSet) (recordSet, func()) {
	// Build and dedup a list of candidate entries. Ignore those without an
	// SVID but otherwise don't check for selector set inclusion yet, since
	// that is a more expensive operation and we could easily have duplicate
	// entries to check.
	records, recordsDone := allocRecordSet()
	for selector := range set {
		index := c.getSelectorIndex(selector)
		for record := range index.records {
			if record.svid == nil {
				continue
			}
			records[record] = struct{}{}
		}
	}

	// Filter out records whose registration entry selectors are not within
	// inside the selector set.
	for record := range records {
		for _, s := range record.entry.Selectors {
			if !set.In(s) {
				delete(records, record)
			}
		}
	}
	return records, recordsDone
}

// getSelectorIndex gets the selector index for the selector. If one doesn't
// exist, it is created.
func (c *Cache) getSelectorIndex(s selector) *selectorIndex {
	index, ok := c.selectors[s]
	if !ok {
		index = newSelectorIndex()
		c.selectors[s] = index
	}
	return index
}

type cacheRecord struct {
	entry *common.RegistrationEntry
	svid  *X509SVID
	subs  map[*subscriber]struct{}
}

func newCacheRecord() *cacheRecord {
	return &cacheRecord{
		subs: make(map[*subscriber]struct{}),
	}
}

type selectorIndex struct {
	// subs holds the subscriptions related to this selector
	subs map[*subscriber]struct{}

	// records holds the cache records related to this selector
	records map[*cacheRecord]struct{}
}

func (x *selectorIndex) isEmpty() bool {
	return len(x.subs) == 0 && len(x.records) == 0
}

func newSelectorIndex() *selectorIndex {
	return &selectorIndex{
		subs:    make(map[*subscriber]struct{}),
		records: make(map[*cacheRecord]struct{}),
	}
}

func sortIdentities(identities []Identity) {
	sort.Slice(identities, func(a, b int) bool {
		return identities[a].Entry.EntryId < identities[b].Entry.EntryId
	})
}

func makeIdentity(record *cacheRecord) Identity {
	return Identity{
		Entry:      record.entry,
		SVID:       record.svid.Chain,
		PrivateKey: record.svid.PrivateKey,
	}
}
