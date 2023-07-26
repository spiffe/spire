package storecache

import (
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
)

// Record holds the latests cached SVID with its context
type Record struct {
	// ID holds entry ID
	ID string
	// Entry holds registration entry for record
	Entry *common.RegistrationEntry
	// ExpiresAt is the expiration time for SVID
	ExpiresAt time.Time
	// Svid holds a valid X509-SVID
	Svid *cache.X509SVID
	// Revision is the current cache record version
	Revision int64
	// Bundles holds trust domain bundle together with federated bundle
	Bundles map[spiffeid.TrustDomain]*spiffebundle.Bundle
	// HandledEntry holds the previous entry revision. It is useful to define
	// what changed between versions.
	HandledEntry *common.RegistrationEntry
}

// cachedRecord holds internal cached SVIDs
type cachedRecord struct {
	entry *common.RegistrationEntry
	svid  *cache.X509SVID

	revision     int64
	handled      int64
	handledEntry *common.RegistrationEntry
}

// Config is the store cache configuration
type Config struct {
	Log         logrus.FieldLogger
	TrustDomain spiffeid.TrustDomain
}

type Cache struct {
	c *Config

	mtx sync.RWMutex

	// bundles holds the latests bundles
	bundles map[spiffeid.TrustDomain]*spiffebundle.Bundle
	// records holds all the latests SVIDs with its entries
	records map[string]*cachedRecord

	// staleEntries holds stale registration entries
	staleEntries map[string]bool
}

func New(config *Config) *Cache {
	return &Cache{
		c:            config,
		records:      make(map[string]*cachedRecord),
		bundles:      make(map[spiffeid.TrustDomain]*spiffebundle.Bundle),
		staleEntries: make(map[string]bool),
	}
}

// UpdateEntries using `UpdateEntries` updates and validates latests entries,
// record's revision number is incremented on each record baed on:
// - Knowledge or when the SVID for that entry changes
// - Knowledge when the bundle changes
// - Knowledge when a federated bundle related to an storable entry changes
func (c *Cache) UpdateEntries(update *cache.UpdateEntries, checkSVID func(*common.RegistrationEntry, *common.RegistrationEntry, *cache.X509SVID) bool) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	// Remove bundles that no longer exist. The bundle for the agent trust
	// domain should NOT be removed even if not present (which should only be
	// the case if there is a bug on the server) since it is necessary to
	// authenticate the server.
	bundlesRemoved := make(map[spiffeid.TrustDomain]bool)
	for id := range c.bundles {
		if _, ok := update.Bundles[id]; !ok && id != c.c.TrustDomain {
			bundlesRemoved[id] = true
			// bundle no longer exists.
			c.c.Log.WithField(telemetry.TrustDomainID, id).Debug("Bundle removed")
			delete(c.bundles, id)
		}
	}

	// Update bundles with changes, populating a "changed" set that we can
	// check when processing registration entries to know if they need to
	// increment revision.
	bundleChanged := make(map[spiffeid.TrustDomain]bool)
	for id, bundle := range update.Bundles {
		existing, ok := c.bundles[id]
		if !(ok && existing.Equal(bundle)) {
			if !ok {
				c.c.Log.WithField(telemetry.TrustDomainID, id).Debug("Bundle added")
			} else {
				c.c.Log.WithField(telemetry.TrustDomainID, id).Debug("Bundle updated")
			}
			bundleChanged[id] = true
			c.bundles[id] = bundle
		}
	}
	trustDomainBundleChanged := bundleChanged[c.c.TrustDomain]

	// Remove records of registration entries that no longer exist
	for id, record := range c.records {
		if _, ok := update.RegistrationEntries[id]; !ok {
			// Record is marked as removed and already processed by store service,
			// since the value of latest handled is equal to current revision
			if record.entry == nil && record.revision == record.handled {
				delete(c.records, id)
				c.c.Log.WithFields(logrus.Fields{
					telemetry.Entry:    id,
					telemetry.SPIFFEID: record.handledEntry.SpiffeId,
				}).Debug("Entry removed")
				continue
			}

			if record.entry == nil {
				// Entry waiting to be removed on platform
				continue
			}

			c.c.Log.WithFields(logrus.Fields{
				telemetry.Entry:    id,
				telemetry.SPIFFEID: record.entry.SpiffeId,
			}).Debug("Entry marked to be removed")

			// Mark the entry as removed, setting "entry" as 'nil'. The latest handled entry is set as current entry,
			// and increment the revision.
			// The record will be taken by the service to propagate it to SVID Stores.
			// Once the SVID Store plugin removes it from the specific platform, 'revision' will be equal to 'handled'
			record.handledEntry = record.entry
			record.entry = nil
			record.revision++
			delete(c.staleEntries, id)
		}
	}

	// Add/update records for registration entries in the update
	for _, newEntry := range update.RegistrationEntries {
		record, existingEntry := c.updateOrCreateRecord(newEntry)

		entryUpdated := existingEntry == nil || record.entry.RevisionNumber != existingEntry.RevisionNumber

		// TODO: may we separate cases to add more details about why we increment revision?
		switch {
		// Entry revision changed that means entry changed
		case entryUpdated,
			// Increase the revision when the TD bundle changed
			trustDomainBundleChanged,
			// Mark record as stale when a federated bundle changed
			isBundleChanged(record.entry.FederatesWith, bundleChanged),
			// Increase the revision when the federated bundle related with the entry is removed
			isBundleRemoved(record.entry.FederatesWith, bundlesRemoved):
			// Related bundles or entry changed, mark this record as outdated
			record.revision++
		}

		// TODO: in case where entry is updated may we not increment revision and just add it to stale?
		// Then stale will be taken by sync and it will increment revision.
		if checkSVID != nil && checkSVID(existingEntry, newEntry, record.svid) {
			c.staleEntries[newEntry.EntryId] = true
		}

		// Log when entry is updated or created.
		if entryUpdated {
			log := c.c.Log.WithFields(logrus.Fields{
				telemetry.Entry:    newEntry.EntryId,
				telemetry.SPIFFEID: newEntry.SpiffeId,
			})
			if existingEntry != nil {
				log.Debug("Entry updated")
			} else {
				log.Debug("Entry created")
			}
		}
	}
}

// UpdateSVIDs updates cache with latests SVIDs
func (c *Cache) UpdateSVIDs(update *cache.UpdateSVIDs) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	// Add/update records for registration entries in the update
	for entryID, svid := range update.X509SVIDs {
		record, existingEntry := c.records[entryID]
		if !existingEntry {
			c.c.Log.WithField(telemetry.RegistrationID, entryID).Error("Entry not found")
			continue
		}
		// Record is going to be deleted
		if record.entry == nil {
			continue
		}

		record.svid = svid
		// Increment revision since record changed
		record.revision++
		log := c.c.Log.WithFields(logrus.Fields{
			telemetry.Entry:    record.entry.EntryId,
			telemetry.SPIFFEID: record.entry.SpiffeId,
		})
		log.Debug("SVID updated")

		// Cache record is updated, remove it from stale map
		delete(c.staleEntries, entryID)
	}
}

// GetStaleEntries obtains a list of stale entries, that needs new SVIDs
func (c *Cache) GetStaleEntries() []*cache.StaleEntry {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	var staleEntries []*cache.StaleEntry
	for entryID := range c.staleEntries {
		record, ok := c.records[entryID]
		if !ok {
			c.c.Log.WithField(telemetry.RegistrationID, entryID).Debug("Stale marker found for unknown entry. Please fill a bug")
			delete(c.staleEntries, entryID)
			continue
		}

		var expiresAt time.Time
		if record.svid != nil {
			expiresAt = record.svid.Chain[0].NotAfter
		}

		staleEntries = append(staleEntries, &cache.StaleEntry{
			Entry:         record.entry,
			SVIDExpiresAt: expiresAt,
		})
	}

	sort.Slice(staleEntries, func(a, b int) bool {
		return staleEntries[a].Entry.EntryId < staleEntries[b].Entry.EntryId
	})
	return staleEntries
}

// ReadyToStore returns all records that are ready to be stored
func (c *Cache) ReadyToStore() []*Record {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	records := make([]*Record, 0, len(c.records))
	for _, record := range c.records {
		if record.revision > record.handled {
			records = append(records, recordFromCache(record, c.bundles))
		}
	}

	sort.Slice(records, func(a, b int) bool {
		return records[a].ID < records[b].ID
	})
	return records
}

// HandledRecord updates handled revision, and sets the latests processed entry
func (c *Cache) HandledRecord(handledEntry *common.RegistrationEntry, revision int64) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if record, ok := c.records[handledEntry.EntryId]; ok {
		record.handled = revision
		record.handledEntry = handledEntry
	}
}

// Records returns all the records in the cache.
// This function exists only to facilitate testing.
func (c *Cache) Records() []*Record {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	var records []*Record
	for _, r := range c.records {
		records = append(records, recordFromCache(r, c.bundles))
	}

	sort.Slice(records, func(a, b int) bool {
		return records[a].ID < records[b].ID
	})

	return records
}

// updateOrCreateRecord creates a new record if required or updates the existing record.
// In case that the record is updated, the old entry is returned.
func (c *Cache) updateOrCreateRecord(newEntry *common.RegistrationEntry) (*cachedRecord, *common.RegistrationEntry) {
	var existingEntry *common.RegistrationEntry
	record, recordExists := c.records[newEntry.EntryId]
	if !recordExists {
		record = &cachedRecord{
			entry:    newEntry,
			revision: 0,
			// Revision will be incremented after validations
			handled: 0,
		}

		c.records[newEntry.EntryId] = record
	} else {
		existingEntry = record.entry
	}
	record.entry = newEntry
	return record, existingEntry
}

// isBundleChanged indicates whether any federated bundle changed or not
func isBundleChanged(federatesWith []string, bundleChanged map[spiffeid.TrustDomain]bool) bool {
	for _, federatedWith := range federatesWith {
		td, err := spiffeid.TrustDomainFromString(federatedWith)
		if err != nil {
			// There are logs on previous steps that already log this case
			continue
		}

		// In case that a single bundle changed, all the record is marked as outdated
		if bundleChanged[td] {
			return true
		}
	}

	return false
}

// isBundleRemoved indicates if any federated bundle is now removed
func isBundleRemoved(federatesWith []string, bundleRemoved map[spiffeid.TrustDomain]bool) bool {
	for _, federatedWith := range federatesWith {
		td, err := spiffeid.TrustDomainFromString(federatedWith)
		if err != nil {
			// There are logs on previous steps that already log this case
			continue
		}

		// In case a single bundle is removed, all the record is marked as outdated
		if bundleRemoved[td] {
			return true
		}
	}

	return false
}

// recordFromCache parses cache record into storable Record
func recordFromCache(r *cachedRecord, bundles map[spiffeid.TrustDomain]*spiffebundle.Bundle) *Record {
	var expiresAt time.Time
	if r.svid != nil {
		expiresAt = r.svid.Chain[0].NotAfter
	}
	entry := r.entry
	if entry == nil {
		entry = r.handledEntry
	}
	return &Record{
		ID:        entry.EntryId,
		Entry:     r.entry,
		Svid:      r.svid,
		Revision:  r.revision,
		ExpiresAt: expiresAt,
		// TODO: May we filter bundles based in TD and federated bundle?
		Bundles:      bundles,
		HandledEntry: r.handledEntry,
	}
}
