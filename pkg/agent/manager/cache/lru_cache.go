package cache

import (
	"context"
	"crypto/x509"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/backoff"
	"github.com/spiffe/spire/pkg/common/telemetry"
	agentmetrics "github.com/spiffe/spire/pkg/common/telemetry/agent"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
)

const (
	// SVIDCacheMaxSize is the size for the cache
	SVIDCacheMaxSize = 1000
	// SVIDSyncInterval is the interval at which SVIDs are synced with subscribers
	SVIDSyncInterval = 500 * time.Millisecond
	// Default batch size for processing tainted SVIDs
	defaultProcessingBatchSize = 100
)

var (
	// Time interval between SVID batch processing
	processingTaintedX509SVIDInterval = 5 * time.Second
)

// UpdateEntries holds information for an entries update to the cache.
type UpdateEntries struct {
	// Bundles is a set of ALL trust bundles available to the agent, keyed by trust domain
	Bundles map[spiffeid.TrustDomain]*spiffebundle.Bundle

	// TaintedX509Authorities is a set of all tainted X.509 authorities notified by the server.
	TaintedX509Authorities []string

	// TaintedJWTAuthorities is a set of all tainted JWT authorities notified by the server.
	TaintedJWTAuthorities []string

	// RegistrationEntries is a set of all registration entries available to the
	// agent, keyed by registration entry id.
	RegistrationEntries map[string]*common.RegistrationEntry
}

// StaleEntry holds stale entries with SVIDs expiration time
type StaleEntry struct {
	// Entry stale registration entry
	Entry *common.RegistrationEntry
	// SVIDs expiration time
	SVIDExpiresAt time.Time
}

// Cache caches each registration entry, bundles, and JWT SVIDs for the agent.
// The signed X509-SVIDs for those entries are stored in LRU-like cache.
// It allows subscriptions by (workload) selector sets and notifies subscribers when:
//
// 1) a registration entry related to the selectors:
//   - is modified
//   - has a new X509-SVID signed for it
//   - federates with a federated bundle that is updated
//
// 2) the trust bundle for the agent trust domain is updated
//
// When notified, the subscriber is given a WorkloadUpdate containing
// related identities and trust bundles.
//
// The cache does this efficiently by building an index for each unique
// selector it encounters. Each selector index tracks the subscribers (i.e
// workloads) and registration entries that have that selector.
//
// The LRU-like SVID cache has a size limit and expiry period.
//  1. Size limit of SVID cache is a soft limit. If SVID has a subscriber present then
//     that SVID is never removed from cache.
//  2. Least recently used SVIDs are removed from cache only after the cache expiry period has passed.
//     This is done to reduce the overall cache churn.
//  3. Last access timestamp for SVID cache entry is updated when a new subscriber is created
//  4. When a new subscriber is created and there is a cache miss
//     then subscriber needs to wait for next SVID sync event to receive WorkloadUpdate with newly minted SVID
//
// The advantage of above approach is that if agent has entry count less than cache size
// then all SVIDs are cached at all times. If agent has entry count greater than cache size then
// subscribers will continue to get SVID updates (potential delay for first WorkloadUpdate if cache miss)
// and least used SVIDs will be removed from cache which will save memory usage.
// This allows agent to support environments where the active simultaneous workload count
// is a small percentage of the large number of registrations assigned to the agent.
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
type LRUCache struct {
	*BundleCache
	*JWTSVIDCache

	log         logrus.FieldLogger
	trustDomain spiffeid.TrustDomain
	clk         clock.Clock

	metrics telemetry.Metrics

	mu sync.RWMutex

	// records holds the records for registration entries, keyed by registration entry ID
	records map[string]*lruCacheRecord

	// selectors holds the selector indices, keyed by a selector key
	selectors map[selector]*selectorsMapIndex

	// staleEntries holds stale or new registration entries which require new SVID to be stored in cache
	staleEntries map[string]bool

	// bundles holds the trust bundles, keyed by trust domain id (i.e. "spiffe://domain.test")
	bundles map[spiffeid.TrustDomain]*spiffebundle.Bundle

	// svids are stored by entry IDs
	svids map[string]*X509SVID

	subscribeBackoffFn func() backoff.BackOff

	processingBatchSize int
	// used to debug scheduled batchs for tainted authorities
	taintedBatchProcessedCh chan struct{}
}

func NewLRUCache(log logrus.FieldLogger, trustDomain spiffeid.TrustDomain, bundle *Bundle, metrics telemetry.Metrics, clk clock.Clock) *LRUCache {
	return &LRUCache{
		BundleCache:  NewBundleCache(trustDomain, bundle),
		JWTSVIDCache: NewJWTSVIDCache(),

		log:          log,
		metrics:      metrics,
		trustDomain:  trustDomain,
		records:      make(map[string]*lruCacheRecord),
		selectors:    make(map[selector]*selectorsMapIndex),
		staleEntries: make(map[string]bool),
		bundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
			trustDomain: bundle,
		},
		svids: make(map[string]*X509SVID),
		clk:   clk,
		subscribeBackoffFn: func() backoff.BackOff {
			return backoff.NewBackoff(clk, SVIDSyncInterval)
		},
		processingBatchSize: defaultProcessingBatchSize,
	}
}

// Identities is only used by manager tests
// TODO: We should remove this and find a better way
func (c *LRUCache) Identities() []Identity {
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
		out = append(out, makeNewIdentity(record, svid))
	}
	sortIdentities(out)
	return out
}

func (c *LRUCache) Entries() []*common.RegistrationEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]*common.RegistrationEntry, 0, len(c.records))
	for _, record := range c.records {
		out = append(out, record.entry)
	}
	sortEntriesByID(out)
	return out
}

func (c *LRUCache) CountX509SVIDs() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.svids)
}

func (c *LRUCache) CountJWTSVIDs() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.JWTSVIDCache.svids)
}

func (c *LRUCache) CountRecords() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.records)
}

func (c *LRUCache) MatchingRegistrationEntries(selectors []*common.Selector) []*common.RegistrationEntry {
	set, setDone := allocSelectorSet(selectors...)
	defer setDone()

	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.matchingEntries(set)
}

func (c *LRUCache) FetchWorkloadUpdate(selectors []*common.Selector) *WorkloadUpdate {
	set, setDone := allocSelectorSet(selectors...)
	defer setDone()

	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.buildWorkloadUpdate(set)
}

// NewSubscriber creates a subscriber for given selector set.
// Separately call Notify for the first time after this method is invoked to receive latest updates.
func (c *LRUCache) NewSubscriber(selectors []*common.Selector) Subscriber {
	c.mu.Lock()
	defer c.mu.Unlock()

	sub := newLRUCacheSubscriber(c, selectors)
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
func (c *LRUCache) UpdateEntries(update *UpdateEntries, checkSVID func(*common.RegistrationEntry, *common.RegistrationEntry, *X509SVID) bool) {
	c.mu.Lock()
	defer func() { agentmetrics.SetEntriesMapSize(c.metrics, c.CountRecords()) }()
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
		if !(ok && existing.Equal(bundle)) {
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

	entriesRemoved := 0
	// Remove records for registration entries that no longer exist
	for id, record := range c.records {
		if _, ok := update.RegistrationEntries[id]; !ok {
			c.log.WithFields(logrus.Fields{
				telemetry.Entry:    id,
				telemetry.SPIFFEID: record.entry.SpiffeId,
			}).Debug("Entry removed")
			entriesRemoved++

			// built a set of selectors for the record being removed, drop the
			// record for each selector index, and add the entry selectors to
			// the notify set.
			notifySet, notifySetDone := allocSelectorSet(record.entry.Selectors...)
			defer notifySetDone()
			c.delSelectorIndicesRecord(notifySet, record)
			notifySets = append(notifySets, notifySet)
			delete(c.records, id)
			delete(c.svids, id)
			// Remove stale entry since, registration entry is no longer on cache.
			delete(c.staleEntries, id)
		}
	}
	agentmetrics.IncrementEntriesRemoved(c.metrics, entriesRemoved)

	outdatedEntries := make(map[string]struct{})
	entriesUpdated := 0
	entriesCreated := 0

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
		// sure subscribers for the new and existing entry selector sets
		// are notified.
		if selectorsChanged {
			if existingEntry != nil {
				notifySet, notifySetDone := allocSelectorSet(existingEntry.Selectors...)
				defer notifySetDone()
				notifySets = append(notifySets, notifySet)
			}
		}

		if federatedBundlesChanged || selectorsChanged {
			notifySet, notifySetDone := allocSelectorSet(newEntry.Selectors...)
			defer notifySetDone()
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
				entriesUpdated++
			} else {
				log.Debug("Entry created")
				entriesCreated++
			}
		}
	}
	agentmetrics.IncrementEntriesAdded(c.metrics, entriesCreated)
	agentmetrics.IncrementEntriesUpdated(c.metrics, entriesUpdated)

	// entries with active subscribers which are not cached will be put in staleEntries map;
	// irrespective of what svid cache size as we cannot deny identity to a subscriber
	activeSubsByEntryID, recordsWithLastAccessTime := c.syncSVIDsWithSubscribers()
	extraSize := len(c.svids) - SVIDCacheMaxSize

	// delete svids without subscribers and which have not been accessed since svidCacheExpiryTime
	if extraSize > 0 {
		// sort recordsWithLastAccessTime
		sortByTimestamps(recordsWithLastAccessTime)

		for _, record := range recordsWithLastAccessTime {
			if extraSize <= 0 {
				// no need to delete SVIDs any further as cache size <= SVIDCacheMaxSize
				break
			}
			if _, ok := c.svids[record.id]; ok {
				if _, exists := activeSubsByEntryID[record.id]; !exists {
					// remove svid
					c.log.WithField("record_id", record.id).
						WithField("record_timestamp", record.timestamp).
						Debug("Removing SVID record")
					delete(c.svids, record.id)
					extraSize--
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

	// Add message only when there are outdated SVIDs
	if len(outdatedEntries) > 0 {
		c.log.WithField(telemetry.OutdatedSVIDs, len(outdatedEntries)).
			Debug("Updating SVIDs with outdated attributes in cache")
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

func (c *LRUCache) UpdateSVIDs(update *UpdateSVIDs) {
	c.mu.Lock()
	defer func() { agentmetrics.SetSVIDMapSize(c.metrics, c.CountX509SVIDs()) }()
	defer c.mu.Unlock()

	// Allocate a set of selectors that
	notifySet, notifySetDone := allocSelectorSet()
	defer notifySetDone()

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

// TaintX509SVIDs initiates the processing of all cached SVIDs, checking if they are tainted
// by any of the provided authorities.
// It schedules the processing to run asynchronously in batches.
func (c *LRUCache) TaintX509SVIDs(ctx context.Context, taintedX509Authorities []*x509.Certificate) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var entriesToProcess []string
	for key, svid := range c.svids {
		if svid != nil && len(svid.Chain) > 0 {
			entriesToProcess = append(entriesToProcess, key)
		}
	}

	// Check if there are any entries to process before scheduling
	if len(entriesToProcess) == 0 {
		c.log.Debug("No SVID entries to process for tainted X.509 authorities")
		return
	}

	// Schedule the rotation process in a separate goroutine
	go func() {
		c.scheduleRotation(ctx, entriesToProcess, taintedX509Authorities)
	}()

	c.log.WithField(telemetry.Count, len(entriesToProcess)).
		Debug("Scheduled rotation for SVID entries due to tainted X.509 authorities")
}

// GetStaleEntries obtains a list of stale entries
func (c *LRUCache) GetStaleEntries() []*StaleEntry {
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
			Entry:         cachedEntry.entry,
			SVIDExpiresAt: expiresAt,
		})
	}

	return staleEntries
}

// SyncSVIDsWithSubscribers will sync svid cache:
// entries with active subscribers which are not cached will be put in staleEntries map
// records which are not cached for remainder of max cache size will also be put in staleEntries map
func (c *LRUCache) SyncSVIDsWithSubscribers() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.syncSVIDsWithSubscribers()
}

// scheduleRotation processes SVID entries in batches, removing those tainted by X.509 authorities.
// The process continues at regular intervals until all entries have been processed or the context is cancelled.
func (c *LRUCache) scheduleRotation(ctx context.Context, entryIDs []string, taintedX509Authorities []*x509.Certificate) {
	ticker := c.clk.Ticker(processingTaintedX509SVIDInterval)
	defer ticker.Stop()

	// Ensure consistent order for test cases if channel is used
	if c.taintedBatchProcessedCh != nil {
		sort.Strings(entryIDs)
	}

	for {
		// Process entries in batches
		batchSize := min(c.processingBatchSize, len(entryIDs))
		processingEntries := entryIDs[:batchSize]

		c.processTaintedSVIDs(processingEntries, taintedX509Authorities)

		// Remove processed entries from the list
		entryIDs = entryIDs[batchSize:]

		entriesLeftCount := len(entryIDs)
		if entriesLeftCount == 0 {
			c.log.Info("Finished processing all tainted entries")
			c.notifyTaintedBatchProcessed()
			return
		}
		c.log.WithField(telemetry.Count, entriesLeftCount).Info("There are tainted X.509 SVIDs left to be processed")
		c.notifyTaintedBatchProcessed()

		select {
		case <-ticker.C:
		case <-ctx.Done():
			c.log.WithError(ctx.Err()).Warn("Context cancelled, exiting rotation schedule")
			return
		}
	}
}

func (c *LRUCache) notifyTaintedBatchProcessed() {
	if c.taintedBatchProcessedCh != nil {
		c.taintedBatchProcessedCh <- struct{}{}
	}
}

// processTaintedSVIDs identifies and removes tainted SVIDs from the cache that have been signed by the given tainted authorities.
func (c *LRUCache) processTaintedSVIDs(entryIDs []string, taintedX509Authorities []*x509.Certificate) {
	counter := telemetry.StartCall(c.metrics, telemetry.CacheManager, "", telemetry.ProcessTaintedSVIDs)
	defer counter.Done(nil)

	taintedSVIDs := 0

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, entryID := range entryIDs {
		svid, exists := c.svids[entryID]
		if !exists || svid == nil {
			// Skip if the SVID is not in cache or is nil
			continue
		}

		// Check if the SVID is signed by any tainted authority
		isTainted, err := x509util.IsSignedByRoot(svid.Chain, taintedX509Authorities)
		if err != nil {
			c.log.WithError(err).
				WithField(telemetry.RegistrationID, entryID).
				Error("Failed to check if SVID is signed by tainted authority")
			continue
		}
		if isTainted {
			taintedSVIDs++
			delete(c.svids, entryID)
		}
	}

	agentmetrics.AddCacheManagerTaintedSVIDsSample(c.metrics, "", float32(taintedSVIDs))
	c.log.WithField(telemetry.TaintedSVIDs, taintedSVIDs).Info("Tainted X.509 SVIDs")
}

// Notify subscriber of selector set only if all SVIDs for corresponding selector set are cached
// It returns whether all SVIDs are cached or not.
// This method should be retried with backoff to avoid lock contention.
func (c *LRUCache) notifySubscriberIfSVIDAvailable(selectors []*common.Selector, subscriber *lruCacheSubscriber) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	set, setFree := allocSelectorSet(selectors...)
	defer setFree()
	if !c.missingSVIDRecords(set) {
		c.notify(subscriber)
		return true
	}
	return false
}

func (c *LRUCache) SubscribeToWorkloadUpdates(ctx context.Context, selectors Selectors) (Subscriber, error) {
	return c.subscribeToWorkloadUpdates(ctx, selectors, nil)
}

func (c *LRUCache) subscribeToWorkloadUpdates(ctx context.Context, selectors Selectors, notifyCallbackFn func()) (Subscriber, error) {
	subscriber := c.NewSubscriber(selectors)
	bo := c.subscribeBackoffFn()

	sub, ok := subscriber.(*lruCacheSubscriber)
	if !ok {
		return nil, fmt.Errorf("unexpected subscriber type %T", sub)
	}

	if len(selectors) == 0 {
		if notifyCallbackFn != nil {
			notifyCallbackFn()
		}
		c.notify(sub)
		return subscriber, nil
	}

	// block until all svids are cached and subscriber is notified
	for {
		// notifyCallbackFn is used for testing
		if c.notifySubscriberIfSVIDAvailable(selectors, sub) {
			if notifyCallbackFn != nil {
				notifyCallbackFn()
			}
			return subscriber, nil
		}
		c.log.WithField(telemetry.Selectors, selectors).Info("Waiting for SVID to get cached")
		// used for testing
		if notifyCallbackFn != nil {
			notifyCallbackFn()
		}

		select {
		case <-ctx.Done():
			subscriber.Finish()
			return nil, ctx.Err()
		case <-c.clk.After(bo.NextBackOff()):
		}
	}
}

func (c *LRUCache) missingSVIDRecords(set selectorSet) bool {
	records, recordsDone := c.getRecordsForSelectors(set)
	defer recordsDone()

	for record := range records {
		if _, exists := c.svids[record.entry.EntryId]; !exists {
			return true
		}
	}
	return false
}

func (c *LRUCache) updateLastAccessTimestamp(selectors []*common.Selector) {
	set, setFree := allocSelectorSet(selectors...)
	defer setFree()

	records, recordsDone := c.getRecordsForSelectors(set)
	defer recordsDone()

	now := c.clk.Now().UnixMilli()
	for record := range records {
		// Set lastAccessTimestamp so that svid LRU cache can be cleaned based on this timestamp
		record.lastAccessTimestamp = now
	}
}

// entries with active subscribers which are not cached will be put in staleEntries map
// records which are not cached for remainder of max cache size will also be put in staleEntries map
func (c *LRUCache) syncSVIDsWithSubscribers() (map[string]struct{}, []recordAccessEvent) {
	activeSubsByEntryID := make(map[string]struct{})
	lastAccessTimestamps := make([]recordAccessEvent, 0, len(c.records))

	// iterate over all selectors from cached entries and obtain:
	// 1. entries that have active subscribers
	//   1.1 if those entries don't have corresponding SVID cached then put them in staleEntries
	//       so that SVID will be cached in next sync
	// 2. get lastAccessTimestamp of each entry
	for id, record := range c.records {
		for _, sel := range record.entry.Selectors {
			if index, ok := c.selectors[makeSelector(sel)]; ok && index != nil {
				if len(index.subs) > 0 {
					if _, ok := c.svids[record.entry.EntryId]; !ok {
						c.staleEntries[id] = true
					}
					activeSubsByEntryID[id] = struct{}{}
					break
				}
			}
		}
		lastAccessTimestamps = append(lastAccessTimestamps, newRecordAccessEvent(record.lastAccessTimestamp, id))
	}

	remainderSize := SVIDCacheMaxSize - len(c.svids)
	// add records which are not cached for remainder of cache size
	for id := range c.records {
		if len(c.staleEntries) >= remainderSize {
			break
		}
		if _, svidCached := c.svids[id]; !svidCached {
			if _, ok := c.staleEntries[id]; !ok {
				c.staleEntries[id] = true
			}
		}
	}

	return activeSubsByEntryID, lastAccessTimestamps
}

func (c *LRUCache) updateOrCreateRecord(newEntry *common.RegistrationEntry) (*lruCacheRecord, *common.RegistrationEntry) {
	var existingEntry *common.RegistrationEntry
	record, recordExists := c.records[newEntry.EntryId]
	if !recordExists {
		record = newLRUCacheRecord()
		c.records[newEntry.EntryId] = record
	} else {
		existingEntry = record.entry
	}
	record.entry = newEntry
	return record, existingEntry
}

func (c *LRUCache) diffSelectors(existingEntry, newEntry *common.RegistrationEntry, added, removed selectorSet) {
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

func (c *LRUCache) diffFederatesWith(existingEntry, newEntry *common.RegistrationEntry, added, removed stringSet) {
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

func (c *LRUCache) addSelectorIndicesRecord(selectors selectorSet, record *lruCacheRecord) {
	for selector := range selectors {
		c.addSelectorIndexRecord(selector, record)
	}
}

func (c *LRUCache) addSelectorIndexRecord(s selector, record *lruCacheRecord) {
	index := c.getSelectorIndexForWrite(s)
	index.records[record] = struct{}{}
}

func (c *LRUCache) delSelectorIndicesRecord(selectors selectorSet, record *lruCacheRecord) {
	for selector := range selectors {
		c.delSelectorIndexRecord(selector, record)
	}
}

// delSelectorIndexRecord removes the record from the selector index. If
// the selector index is empty afterwards, it is also removed.
func (c *LRUCache) delSelectorIndexRecord(s selector, record *lruCacheRecord) {
	index, ok := c.selectors[s]
	if ok {
		delete(index.records, record)
		if index.isEmpty() {
			delete(c.selectors, s)
		}
	}
}

func (c *LRUCache) addSelectorIndexSub(s selector, sub *lruCacheSubscriber) {
	index := c.getSelectorIndexForWrite(s)
	index.subs[sub] = struct{}{}
}

// delSelectorIndexSub removes the subscription from the selector index. If
// the selector index is empty afterwards, it is also removed.
func (c *LRUCache) delSelectorIndexSub(s selector, sub *lruCacheSubscriber) {
	index, ok := c.selectors[s]
	if ok {
		delete(index.subs, sub)
		if index.isEmpty() {
			delete(c.selectors, s)
		}
	}
}

func (c *LRUCache) unsubscribe(sub *lruCacheSubscriber) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for selector := range sub.set {
		c.delSelectorIndexSub(selector, sub)
	}
}

func (c *LRUCache) notifyAll() {
	subs, subsDone := c.allSubscribers()
	defer subsDone()
	for sub := range subs {
		c.notify(sub)
	}
}

func (c *LRUCache) notifyBySelectorSet(sets ...selectorSet) {
	notifiedSubs, notifiedSubsDone := allocLRUCacheSubscriberSet()
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

func (c *LRUCache) notify(sub *lruCacheSubscriber) {
	update := c.buildWorkloadUpdate(sub.set)
	sub.notify(update)
}

func (c *LRUCache) allSubscribers() (lruCacheSubscriberSet, func()) {
	subs, subsDone := allocLRUCacheSubscriberSet()
	for _, index := range c.selectors {
		for sub := range index.subs {
			subs[sub] = struct{}{}
		}
	}
	return subs, subsDone
}

func (c *LRUCache) getSubscribers(set selectorSet) (lruCacheSubscriberSet, func()) {
	subs, subsDone := allocLRUCacheSubscriberSet()
	for s := range set {
		if index := c.getSelectorIndexForRead(s); index != nil {
			for sub := range index.subs {
				subs[sub] = struct{}{}
			}
		}
	}
	return subs, subsDone
}

func (c *LRUCache) matchingIdentities(set selectorSet) []Identity {
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
			out = append(out, makeNewIdentity(record, svid))
		}
	}
	sortIdentities(out)
	return out
}

func (c *LRUCache) matchingEntries(set selectorSet) []*common.RegistrationEntry {
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
	sortEntriesByID(out)
	return out
}

func (c *LRUCache) buildWorkloadUpdate(set selectorSet) *WorkloadUpdate {
	w := &WorkloadUpdate{
		Bundle:           c.bundles[c.trustDomain],
		FederatedBundles: make(map[spiffeid.TrustDomain]*spiffebundle.Bundle),
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

func (c *LRUCache) getRecordsForSelectors(set selectorSet) (lruCacheRecordSet, func()) {
	// Build and dedup a list of candidate entries. Don't check for selector set inclusion yet, since
	// that is a more expensive operation and we could easily have duplicate
	// entries to check.
	records, recordsDone := allocLRUCacheRecordSet()
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
func (c *LRUCache) getSelectorIndexForWrite(s selector) *selectorsMapIndex {
	index, ok := c.selectors[s]
	if !ok {
		index = newSelectorsMapIndex()
		c.selectors[s] = index
	}
	return index
}

// getSelectorIndexForRead gets the selector index for the selector. If one
// doesn't exist, nil is returned. Callers should hold the read or write lock.
// If the index is being modified, callers should use getSelectorIndexForWrite
// instead.
func (c *LRUCache) getSelectorIndexForRead(s selector) *selectorsMapIndex {
	if index, ok := c.selectors[s]; ok {
		return index
	}
	return nil
}

type lruCacheRecord struct {
	entry               *common.RegistrationEntry
	subs                map[*lruCacheSubscriber]struct{}
	lastAccessTimestamp int64
}

func newLRUCacheRecord() *lruCacheRecord {
	return &lruCacheRecord{
		subs: make(map[*lruCacheSubscriber]struct{}),
	}
}

type selectorsMapIndex struct {
	// subs holds the subscriptions related to this selector
	subs map[*lruCacheSubscriber]struct{}

	// records holds the cache records related to this selector
	records map[*lruCacheRecord]struct{}
}

func (x *selectorsMapIndex) isEmpty() bool {
	return len(x.subs) == 0 && len(x.records) == 0
}

func newSelectorsMapIndex() *selectorsMapIndex {
	return &selectorsMapIndex{
		subs:    make(map[*lruCacheSubscriber]struct{}),
		records: make(map[*lruCacheRecord]struct{}),
	}
}

func sortByTimestamps(records []recordAccessEvent) {
	sort.Slice(records, func(a, b int) bool {
		return records[a].timestamp < records[b].timestamp
	})
}

func makeNewIdentity(record *lruCacheRecord, svid *X509SVID) Identity {
	return Identity{
		Entry:      record.entry,
		SVID:       svid.Chain,
		PrivateKey: svid.PrivateKey,
	}
}

type recordAccessEvent struct {
	timestamp int64
	id        string
}

func newRecordAccessEvent(timestamp int64, id string) recordAccessEvent {
	return recordAccessEvent{timestamp: timestamp, id: id}
}
