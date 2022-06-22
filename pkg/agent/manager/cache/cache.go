package cache

import (
	"crypto"
	"crypto/x509"
	"sort"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
)

const (
	DefaultMaxSvidCacheSize      = 1000
	DefaultSVIDCacheExpiryPeriod = 1 * time.Hour
)

type Selectors []*common.Selector
type Bundle = bundleutil.Bundle

// Identity holds the data for a single workload identity
type Identity struct {
	Entry      *common.RegistrationEntry
	SVID       []*x509.Certificate
	PrivateKey crypto.Signer
}

// WorkloadUpdate is used to convey workload information to cache subscribers
type WorkloadUpdate struct {
	Identities       []Identity
	Bundle           *bundleutil.Bundle
	FederatedBundles map[spiffeid.TrustDomain]*bundleutil.Bundle
}

func (u *WorkloadUpdate) HasIdentity() bool {
	return len(u.Identities) > 0
}

// Update holds information for an entries update to the cache.
type UpdateEntries struct {
	// Bundles is a set of ALL trust bundles available to the agent, keyed by trust domain
	Bundles map[spiffeid.TrustDomain]*bundleutil.Bundle

	// RegistrationEntries is a set of ALL registration entries available to the
	// agent, keyed by registration entry id.
	RegistrationEntries map[string]*common.RegistrationEntry
}

// Update holds information for an SVIDs update to the cache.
type UpdateSVIDs struct {
	// X509SVIDs is a set of updated X509-SVIDs that should be merged into
	// the cache, keyed by registration entry id.
	X509SVIDs map[string]*X509SVID
}

// X509SVID holds onto the SVID certificate chain and private key.
type X509SVID struct {
	Chain      []*x509.Certificate
	PrivateKey crypto.Signer
}

// Cache caches each registration entry, bundles, and JWT SVIDs for the agent.
// The signed X509-SVIDs for those entries are stored in LRU-like cache.
// It allows subscriptions by (workload) selector sets and notifies subscribers when:
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
// The LRU-like SVID cache has configurable size limit and expiry period.
// 1. Size limit of SVID cache is a soft limit which means if SVID has a subscriber present then
//    that SVID is never removed from cache.
// 2. Least recently used SVIDs are removed from cache only after the cache expiry period has passed.
//    This is done to reduce the overall cache churn.
// 3. Last access timestamp for SVID cache entry is updated when a new subscriber is created
// 4. When a new subscriber is created and if there is a cache miss
//    then subscriber needs to wait for next SVID sync event to receive WorkloadUpdate with newly minted SVID
//
// The advantage of above approach is that if agent has entry count less than cache size
// then all SVIDs are cached at all times. If agent has entry count greater than cache size then
// subscribers will continue to get SVID updates (potential delay for first WorkloadUpdate if cache miss)
// and least used SVIDs will be removed from cache which will save memory usage.
// It will allow agent to support large number of registrations.
//
//
// When registration entries are added/updated/removed, the set of relevant
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
// relevant objects for each subscriber causes HUGE amounts of memory pressure
// which adds non-trivial amounts of latency and causes a giant memory spike
// that could OOM the agent on smaller VMs. For this reason, the cache is
// presumed to own ALL data passing in and out of the cache. Producers and
// consumers MUST NOT mutate the data.
type Cache struct {
	*BundleCache
	*JWTSVIDCache

	log         logrus.FieldLogger
	trustDomain spiffeid.TrustDomain
	clk         clock.Clock

	metrics telemetry.Metrics

	mu sync.RWMutex

	// records holds the records for registration entries, keyed by registration entry ID
	records map[string]*cacheRecord

	// selectors holds the selector indices, keyed by a selector key
	selectors map[selector]*selectorIndex

	// staleEntries holds stale or new registration entries which require new SVID to be stored in cache
	staleEntries map[string]bool

	// bundles holds the trust bundles, keyed by trust domain id (i.e. "spiffe://domain.test")
	bundles map[spiffeid.TrustDomain]*bundleutil.Bundle

	// svids are stored by entry IDs
	svids map[string]*X509SVID

	// maxSVIDCacheSize is a soft limit of max number of SVIDs that would be stored in cache
	maxSvidCacheSize int

	// svidCacheExpiryPeriod is a period after which svids that don't have subscribers will be removed from cache
	svidCacheExpiryPeriod time.Duration
}

// StaleEntry holds stale or outdated entries which require new SVID with old SVIDs expiration time (if present)
type StaleEntry struct {
	// Entry stale registration entry
	Entry *common.RegistrationEntry
	// SVIDs expiration time
	ExpiresAt time.Time
}

func New(log logrus.FieldLogger, trustDomain spiffeid.TrustDomain, bundle *Bundle, metrics telemetry.Metrics,
	maxSvidCacheSize int, svidCacheExpiryPeriod time.Duration, clk clock.Clock) *Cache {
	if maxSvidCacheSize == 0 {
		maxSvidCacheSize = DefaultMaxSvidCacheSize
	}

	if svidCacheExpiryPeriod == 0 {
		svidCacheExpiryPeriod = DefaultSVIDCacheExpiryPeriod
	}

	return &Cache{
		BundleCache:  NewBundleCache(trustDomain, bundle),
		JWTSVIDCache: NewJWTSVIDCache(),

		log:          log,
		metrics:      metrics,
		trustDomain:  trustDomain,
		records:      make(map[string]*cacheRecord),
		selectors:    make(map[selector]*selectorIndex),
		staleEntries: make(map[string]bool),
		bundles: map[spiffeid.TrustDomain]*bundleutil.Bundle{
			trustDomain: bundle,
		},
		svids:                 make(map[string]*X509SVID),
		maxSvidCacheSize:      maxSvidCacheSize,
		svidCacheExpiryPeriod: svidCacheExpiryPeriod,
		clk:                   clk,
	}
}

// Identities is only used by manager tests
// TODO: We should remove this and find a better way
func (c *Cache) Identities() []Identity {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]Identity, 0, len(c.records))
	for _, record := range c.records {
		svid, ok := c.svids[record.entry.EntryId]
		if !ok {
			// The record does not have an SVID yet and should not be returned
			// from the cache.
			continue
		}
		out = append(out, makeIdentity(record, svid))
	}
	sortIdentities(out)
	return out
}

func (c *Cache) Entries() []*common.RegistrationEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]*common.RegistrationEntry, 0, len(c.records))
	for _, record := range c.records {
		out = append(out, record.entry)
	}
	sortEntries(out)
	return out
}

func (c *Cache) CountSVIDs() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.svids)
}

func (c *Cache) MatchingRegistrationEntries(selectors []*common.Selector) []*common.RegistrationEntry {
	set, setDone := allocSelectorSet(selectors...)
	defer setDone()

	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.matchingEntries(set)
}

func (c *Cache) FetchWorkloadUpdate(selectors []*common.Selector) *WorkloadUpdate {
	set, setDone := allocSelectorSet(selectors...)
	defer setDone()

	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.buildWorkloadUpdate(set)
}

// SubscribeToWorkloadUpdates creates a subscriber for given selector set.
// Separately call Notify for the first time after this method is invoked to receive latest updates.
func (c *Cache) SubscribeToWorkloadUpdates(selectors []*common.Selector) Subscriber {
	c.mu.Lock()
	defer c.mu.Unlock()

	sub := newSubscriber(c, selectors)
	for s := range sub.set {
		c.addSelectorIndexSub(s, sub)
	}
	// update lastAccessTimestamp of records containing provided selectors
	c.updateLastAccessTimestamp(selectors)
	return sub
}

// UpdateEntries updates the cache with the provided registration entries and bundles and
// notifies impacted subscribers. The checkSVID callback, if provided, is used to determine
// if the SVID for the entry is stale, or otherwise in need of rotation. Entries marked stale
// through the checkSVID callback are returned from GetStaleEntries() until the SVID is
// updated through a call to UpdateSVIDs.
func (c *Cache) UpdateEntries(update *UpdateEntries, checkSVID func(*common.RegistrationEntry, *common.RegistrationEntry, *X509SVID) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Remove bundles that no longer exist. The bundle for the agent trust
	// domain should NOT be removed even if not present (which should only be
	// the case if there is a bug on the server) since it is necessary to
	// authenticate the server.
	bundleRemoved := false
	for id := range c.bundles {
		if _, ok := update.Bundles[id]; !ok && id != c.trustDomain {
			bundleRemoved = true
			// bundle no longer exists.
			c.log.WithField(telemetry.TrustDomainID, id).Debug("Bundle removed")
			delete(c.bundles, id)
		}
	}

	// Update bundles with changes, populating a "changed" set that we can
	// check when processing registration entries to know if they need to spawn
	// a notification.
	bundleChanged := make(map[spiffeid.TrustDomain]bool)
	for id, bundle := range update.Bundles {
		existing, ok := c.bundles[id]
		if !(ok && existing.EqualTo(bundle)) {
			if !ok {
				c.log.WithField(telemetry.TrustDomainID, id).Debug("Bundle added")
			} else {
				c.log.WithField(telemetry.TrustDomainID, id).Debug("Bundle updated")
			}
			bundleChanged[id] = true
			c.bundles[id] = bundle
		}
	}
	trustDomainBundleChanged := bundleChanged[c.trustDomain]

	// Allocate sets from the pool to track changes to selectors and
	// federatesWith declarations. These sets must be cleared after EACH use
	// and returned to their respective pools when done processing the
	// updates.
	notifySets := make([]selectorSet, 0)
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
				telemetry.Entry:    id,
				telemetry.SPIFFEID: record.entry.SpiffeId,
			}).Debug("Entry removed")

			// built a set of selectors for the record being removed, drop the
			// record for each selector index, and add the entry selectors to
			// the notify set.
			clearSelectorSet(selRem)
			selRem.Merge(record.entry.Selectors...)
			c.delSelectorIndicesRecord(selRem, record)
			notifySets = append(notifySets, selRem)
			delete(c.records, id)
			delete(c.svids, id)
			// Remove stale entry since, registration entry is no longer on cache.
			delete(c.staleEntries, id)
		}
	}

	outdatedEntries := make(map[string]struct{})

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
		selectorsChanged := len(selAdd) > 0 || len(selRem) > 0
		c.addSelectorIndicesRecord(selAdd, record)
		c.delSelectorIndicesRecord(selRem, record)

		// Determine if there were changes to FederatesWith declarations or
		// if any federated bundles related to the entry were updated.
		c.diffFederatesWith(existingEntry, newEntry, fedAdd, fedRem)
		federatedBundlesChanged := len(fedAdd) > 0 || len(fedRem) > 0
		if !federatedBundlesChanged {
			for _, id := range newEntry.FederatesWith {
				td, err := spiffeid.TrustDomainFromString(id)
				if err != nil {
					c.log.WithFields(logrus.Fields{
						telemetry.TrustDomainID: id,
						logrus.ErrorKey:         err,
					}).Warn("Invalid federated trust domain")
					continue
				}
				if bundleChanged[td] {
					federatedBundlesChanged = true
					break
				}
			}
		}

		// If any selectors or federated bundles were changed, then make
		// sure subscribers for the new and extisting entry selector sets
		// are notified.
		if selectorsChanged {
			if existingEntry != nil {
				notifySet, selSetDone := allocSelectorSet()
				defer selSetDone()
				notifySet.Merge(existingEntry.Selectors...)
				notifySets = append(notifySets, notifySet)
			}
		}

		if federatedBundlesChanged || selectorsChanged {
			notifySet, selSetDone := allocSelectorSet()
			defer selSetDone()
			notifySet.Merge(newEntry.Selectors...)
			notifySets = append(notifySets, notifySet)
		}

		// Identify stale/outdated entries
		if existingEntry != nil && existingEntry.RevisionNumber != newEntry.RevisionNumber {
			outdatedEntries[newEntry.EntryId] = struct{}{}
		}

		// Log all the details of the update to the DEBUG log
		if federatedBundlesChanged || selectorsChanged {
			log := c.log.WithFields(logrus.Fields{
				telemetry.Entry:    newEntry.EntryId,
				telemetry.SPIFFEID: newEntry.SpiffeId,
			})
			if len(selAdd) > 0 {
				log = log.WithField(telemetry.SelectorsAdded, len(selAdd))
			}
			if len(selRem) > 0 {
				log = log.WithField(telemetry.SelectorsRemoved, len(selRem))
			}
			if len(fedAdd) > 0 {
				log = log.WithField(telemetry.FederatedAdded, len(fedAdd))
			}
			if len(fedRem) > 0 {
				log = log.WithField(telemetry.FederatedRemoved, len(fedRem))
			}
			if existingEntry != nil {
				log.Debug("Entry updated")
			} else {
				log.Debug("Entry created")
			}
		}
	}

	// entries with active subscribers which are not cached will be put in staleEntries map
	activeSubs, recordsWithLastAccessTime := c.syncSVIDs()
	extraSize := len(c.svids) - c.maxSvidCacheSize

	// delete svids without subscribers and which have not been accessed since svidCacheExpiryTime
	if extraSize > 0 {
		// sort recordsWithLastAccessTime
		sortTimestamps(recordsWithLastAccessTime)
		now := c.clk.Now()
		svidCacheExpiryTime := now.Add(-1 * c.svidCacheExpiryPeriod).UnixMilli()
		for _, record := range recordsWithLastAccessTime {
			if extraSize <= 0 {
				// no need to delete SVIDs any further as cache size <= maxSvidCacheSize
				break
			}
			if _, ok := c.svids[record.id]; ok {
				if _, exists := activeSubs[record.id]; !exists {
					// remove svid if it has not been accessed since svidCacheExpiryTime
					if record.timestamp < svidCacheExpiryTime {
						c.log.WithField("record_id", record.id).
							WithField("record_timestamp", record.timestamp).
							Debug("Removing SVID record")
						delete(c.svids, record.id)
						extraSize--
					}
				}
			}
		}
	}

	// Update all stale svids or svids whose registration entry is outdated
	for id, svid := range c.svids {
		if _, ok := outdatedEntries[id]; ok || (checkSVID != nil && checkSVID(nil, c.records[id].entry, svid)) {
			c.staleEntries[id] = true
		}
	}

	if bundleRemoved || len(bundleChanged) > 0 {
		c.BundleCache.Update(c.bundles)
	}

	if trustDomainBundleChanged {
		c.notifyAll()
	} else {
		c.notifyBySelectorSet(notifySets...)
	}
}

func (c *Cache) UpdateSVIDs(update *UpdateSVIDs) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Allocate a set of selectors that
	notifySet, selSetDone := allocSelectorSet()
	defer selSetDone()

	// Add/update records for registration entries in the update
	for entryID, svid := range update.X509SVIDs {
		record, existingEntry := c.records[entryID]
		if !existingEntry {
			c.log.WithField(telemetry.RegistrationID, entryID).Error("Entry not found")
			continue
		}

		c.svids[entryID] = svid
		notifySet.Merge(record.entry.Selectors...)
		log := c.log.WithFields(logrus.Fields{
			telemetry.Entry:    record.entry.EntryId,
			telemetry.SPIFFEID: record.entry.SpiffeId,
		})
		log.Debug("SVID updated")

		// Registration entry is updated, remove it from stale map
		delete(c.staleEntries, entryID)
		c.notifyBySelectorSet(notifySet)
		clearSelectorSet(notifySet)
	}
}

// GetStaleEntries obtains a list of stale entries
func (c *Cache) GetStaleEntries() []*StaleEntry {
	c.mu.Lock()
	defer c.mu.Unlock()

	var staleEntries []*StaleEntry
	for entryID := range c.staleEntries {
		cachedEntry, ok := c.records[entryID]
		if !ok {
			c.log.WithField(telemetry.RegistrationID, entryID).Debug("Stale marker found for unknown entry. Please fill a bug")
			delete(c.staleEntries, entryID)
			continue
		}

		var expiresAt time.Time
		if cachedSvid, ok := c.svids[entryID]; ok {
			expiresAt = cachedSvid.Chain[0].NotAfter
		}

		staleEntries = append(staleEntries, &StaleEntry{
			Entry:     cachedEntry.entry,
			ExpiresAt: expiresAt,
		})
	}

	return staleEntries
}

// SyncSVIDsWithSubscribers will sync svid cache:
// entries with active subscribers which are not cached will be put in staleEntries map
// records which are not cached for remainder of max cache size will also be put in staleEntries map
func (c *Cache) SyncSVIDsWithSubscribers() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.syncSVIDs()
}

// Notify subscribers of selector set only if all SVIDs for corresponding selector set are cached
// It returns whether all SVIDs are cached or not.
// This method should be retried with backoff to avoid lock contention.
func (c *Cache) Notify(selectors []*common.Selector) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.missingSVIDRecords(selectors)) == 0 {
		set, setFree := allocSelectorSet(selectors...)
		defer setFree()
		c.notifyBySelectorSet(set)
		return true
	}
	return false
}

func (c *Cache) missingSVIDRecords(selectors []*common.Selector) []*StaleEntry {
	set, setFree := allocSelectorSet(selectors...)
	defer setFree()

	records, recordsDone := c.getRecordsForSelectors(set)
	defer recordsDone()

	if len(records) == 0 {
		return nil
	}
	out := make([]*StaleEntry, 0, len(records))
	for record := range records {
		if _, ok := c.svids[record.entry.EntryId]; !ok {
			out = append(out, &StaleEntry{
				Entry: record.entry,
			})
		}
	}
	return out
}

func (c *Cache) updateLastAccessTimestamp(selectors []*common.Selector) {
	set, setFree := allocSelectorSet(selectors...)
	defer setFree()

	records, recordsDone := c.getRecordsForSelectors(set)
	defer recordsDone()

	for record := range records {
		// Set lastAccessTimestamp so that svid LRU cache can be cleaned based on this timestamp
		record.lastAccessTimestamp = c.clk.Now().UnixMilli()
	}
}

// entries with active subscribers which are not cached will be put in staleEntries map
// records which are not cached for remainder of max cache size will also be put in staleEntries map
func (c *Cache) syncSVIDs() (map[string]struct{}, []record) {
	activeSubs := make(map[string]struct{})
	lastAccessTimestamps := make([]record, len(c.records))

	i := 0
	for id, record := range c.records {
		for _, sel := range record.entry.Selectors {
			if index, ok := c.selectors[makeSelector(sel)]; ok && index != nil {
				if len(index.subs) > 0 {
					if _, ok := c.svids[record.entry.EntryId]; !ok {
						c.staleEntries[id] = true
					}
					activeSubs[id] = struct{}{}
					break
				}
			}
		}
		lastAccessTimestamps[i] = newRecord(record.lastAccessTimestamp, id)
		i++
	}

	remainderSize := c.maxSvidCacheSize - len(c.svids)
	// add records which are not cached for remainder of cache size
	for id, _ := range c.records {
		if len(c.staleEntries) >= remainderSize {
			break
		}
		if _, ok := c.svids[id]; !ok {
			if _, ok := c.staleEntries[id]; !ok {
				c.staleEntries[id] = true
			}
		}
	}

	return activeSubs, lastAccessTimestamps
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
	index := c.getSelectorIndexForWrite(s)
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
	index := c.getSelectorIndexForWrite(s)
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

func (c *Cache) notifyBySelectorSet(sets ...selectorSet) {
	notifiedSubs, notifiedSubsDone := allocSubscriberSet()
	defer notifiedSubsDone()
	for _, set := range sets {
		subs, subsDone := c.getSubscribers(set)
		defer subsDone()
		for sub := range subs {
			if _, notified := notifiedSubs[sub]; !notified && sub.set.SuperSetOf(set) {
				c.notify(sub)
				notifiedSubs[sub] = struct{}{}
			}
		}
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
		if index := c.getSelectorIndexForRead(s); index != nil {
			for sub := range index.subs {
				subs[sub] = struct{}{}
			}
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
		if svid, ok := c.svids[record.entry.EntryId]; ok {
			out = append(out, makeIdentity(record, svid))
		}
	}
	sortIdentities(out)
	return out
}

func (c *Cache) matchingEntries(set selectorSet) []*common.RegistrationEntry {
	records, recordsDone := c.getRecordsForSelectors(set)
	defer recordsDone()

	if len(records) == 0 {
		return nil
	}

	// Return identities in ascending "entry id" order to maintain a consistent
	// ordering.
	// TODO: figure out how to determine the "default" identity
	out := make([]*common.RegistrationEntry, 0, len(records))
	for record := range records {
		out = append(out, record.entry)
	}
	sortEntries(out)
	return out
}

func (c *Cache) buildWorkloadUpdate(set selectorSet) *WorkloadUpdate {
	w := &WorkloadUpdate{
		Bundle:           c.bundles[c.trustDomain],
		FederatedBundles: make(map[spiffeid.TrustDomain]*bundleutil.Bundle),
		Identities:       c.matchingIdentities(set),
	}

	// Add in the bundles the workload is federated with.
	for _, identity := range w.Identities {
		for _, federatesWith := range identity.Entry.FederatesWith {
			td, err := spiffeid.TrustDomainFromString(federatesWith)
			if err != nil {
				c.log.WithFields(logrus.Fields{
					telemetry.TrustDomainID: federatesWith,
					logrus.ErrorKey:         err,
				}).Warn("Invalid federated trust domain")
				continue
			}
			if federatedBundle := c.bundles[td]; federatedBundle != nil {
				w.FederatedBundles[td] = federatedBundle
			} else {
				c.log.WithFields(logrus.Fields{
					telemetry.RegistrationID:  identity.Entry.EntryId,
					telemetry.SPIFFEID:        identity.Entry.SpiffeId,
					telemetry.FederatedBundle: federatesWith,
				}).Warn("Federated bundle contents missing")
			}
		}
	}

	return w
}

func (c *Cache) getRecordsForSelectors(set selectorSet) (recordSet, func()) {
	// Build and dedup a list of candidate entries. Don't check for selector set inclusion yet, since
	// that is a more expensive operation and we could easily have duplicate
	// entries to check.
	records, recordsDone := allocRecordSet()
	for selector := range set {
		if index := c.getSelectorIndexForRead(selector); index != nil {
			for record := range index.records {
				records[record] = struct{}{}
			}
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

// getSelectorIndexForWrite gets the selector index for the selector. If one
// doesn't exist, it is created. Callers must hold the write lock. If the index
// is only being read, then getSelectorIndexForRead should be used instead.
func (c *Cache) getSelectorIndexForWrite(s selector) *selectorIndex {
	index, ok := c.selectors[s]
	if !ok {
		index = newSelectorIndex()
		c.selectors[s] = index
	}
	return index
}

// getSelectorIndexForRead gets the selector index for the selector. If one
// doesn't exist, nil is returned. Callers should hold the read or write lock.
// If the index is being modified, callers should use getSelectorIndexForWrite
// instead.
func (c *Cache) getSelectorIndexForRead(s selector) *selectorIndex {
	if index, ok := c.selectors[s]; ok {
		return index
	}
	return nil
}

type cacheRecord struct {
	entry               *common.RegistrationEntry
	subs                map[*subscriber]struct{}
	lastAccessTimestamp int64
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

func sortEntries(entries []*common.RegistrationEntry) {
	sort.Slice(entries, func(a, b int) bool {
		return entries[a].EntryId < entries[b].EntryId
	})
}

func sortTimestamps(records []record) {
	sort.Slice(records, func(a, b int) bool {
		return records[a].timestamp < records[b].timestamp
	})
}

func makeIdentity(record *cacheRecord, svid *X509SVID) Identity {
	return Identity{
		Entry:      record.entry,
		SVID:       svid.Chain,
		PrivateKey: svid.PrivateKey,
	}
}

type record struct {
	timestamp int64
	id        string
}

func newRecord(timestamp int64, id string) record {
	return record{timestamp: timestamp, id: id}
}
