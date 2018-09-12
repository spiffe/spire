package manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"time"

	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	proto "github.com/spiffe/spire/proto/common"
)

// synchronize hits the node api, checks for entries we haven't fetched yet, and fetches them.
func (m *manager) synchronize() (err error) {
	var regEntries map[string]*proto.RegistrationEntry
	var cEntryRequests = entryRequests{}

	regEntries, _, err = m.fetchUpdates(nil)
	if err != nil {
		return err
	}

	m.clearStaleCacheEntries(regEntries)

	err = m.checkExpiredCacheEntries(cEntryRequests)
	if err != nil {
		return err
	}

	err = m.checkForNewCacheEntries(regEntries, cEntryRequests)
	if err != nil {
		return err
	}

	err = m.processEntryRequests(cEntryRequests)
	if err != nil {
		return err
	}

	return nil
}

func (m *manager) fetchUpdates(entryRequests map[string]*entryRequest) (map[string]*common.RegistrationEntry, map[string]*node.Svid, error) {
	// Put all the CSRs in an array to make just one call with all the CSRs.
	csrs := [][]byte{}
	if entryRequests != nil {
		for _, entryRequest := range entryRequests {
			m.c.Log.Debugf("Requesting SVID for %v", entryRequest.entry.RegistrationEntry.SpiffeId)
			csrs = append(csrs, entryRequest.CSR)
		}
	}

	update, err := m.client.FetchUpdates(&node.FetchX509SVIDRequest{Csrs: csrs})
	if err != nil {
		return nil, nil, err
	}

	if update.Bundle != nil {
		bundle, err := x509.ParseCertificates(update.Bundle)
		if err != nil {
			return nil, nil, err
		}

		if !m.bundleAlreadyCached(bundle) {
			m.cache.SetBundle(bundle)
		}
	}

	return update.Entries, update.SVIDs, nil
}

func (m *manager) processEntryRequests(entryRequests entryRequests) error {
	if len(entryRequests) == 0 {
		return nil
	}

	// Truncate the number of entry requests we are making if it exceeds the CSR
	// burst limit. The rest of the requests will be made on the next pass
	if len(entryRequests) > node.CSRLimit {
		entryRequests.truncate(node.CSRLimit)
	}

	_, svids, err := m.fetchUpdates(entryRequests)
	if err != nil {
		return err
	}

	if err := m.updateEntriesSVIDs(entryRequests, svids); err != nil {
		return err
	}

	return nil
}

func (m *manager) updateEntriesSVIDs(entryRequestsMap map[string]*entryRequest, svids map[string]*node.Svid) error {
	for _, entryRequest := range entryRequestsMap {
		ce := entryRequest.entry
		svid, ok := svids[ce.RegistrationEntry.SpiffeId]
		if ok {
			cert, err := x509.ParseCertificate(svid.SvidCert)
			if err != nil {
				return err
			}
			// Complete the pre-built cache entry with the SVID and put it on the cache.
			ce.SVID = cert
			m.cache.SetEntry(ce)
		}
	}
	return nil
}

func (m *manager) clearStaleCacheEntries(regEntries map[string]*proto.RegistrationEntry) {
	for _, entry := range m.cache.Entries() {
		if _, ok := regEntries[entry.RegistrationEntry.EntryId]; !ok {
			m.cache.DeleteEntry(entry.RegistrationEntry)
		}
	}
}

func (m *manager) checkExpiredCacheEntries(cEntryRequests entryRequests) error {
	defer m.c.Tel.MeasureSince([]string{"cache_manager", "expiry_check_duration"}, time.Now())

	for _, entry := range m.cache.Entries() {
		ttl := entry.SVID.NotAfter.Sub(time.Now())
		lifetime := entry.SVID.NotAfter.Sub(entry.SVID.NotBefore)
		// If the cached SVID has a remaining lifetime less than 50%, prepare a
		// new entryRequest.
		if ttl < lifetime/2 {
			m.c.Log.Debugf("cache entry ttl for spiffeId %s is less than a half its lifetime", entry.RegistrationEntry.SpiffeId)
			privateKey, csr, err := m.newCSR(entry.RegistrationEntry.SpiffeId)
			if err != nil {
				return err
			}

			bundles := make(map[string][]byte) //TODO: Populate Bundles
			cacheEntry := &cache.Entry{
				RegistrationEntry: entry.RegistrationEntry,
				SVID:              nil,
				PrivateKey:        privateKey,
				Bundles:           bundles,
			}
			cEntryRequests.add(&entryRequest{csr, cacheEntry})
		}
	}

	m.c.Tel.AddSample([]string{"cache_manager", "expiring_svids"}, float32(len(cEntryRequests)))
	return nil
}

func (m *manager) checkForNewCacheEntries(regEntries map[string]*proto.RegistrationEntry, cEntryRequests entryRequests) error {
	for _, regEntry := range regEntries {
		if !m.isAlreadyCached(regEntry) {
			privateKey, csr, err := m.newCSR(regEntry.SpiffeId)
			if err != nil {
				return err
			}

			bundles := make(map[string][]byte) //TODO: Populate Bundles
			cacheEntry := &cache.Entry{
				RegistrationEntry: regEntry,
				SVID:              nil,
				PrivateKey:        privateKey,
				Bundles:           bundles,
			}
			cEntryRequests.add(&entryRequest{csr, cacheEntry})
		}
	}

	return nil
}

func (m *manager) newCSR(spiffeID string) (pk *ecdsa.PrivateKey, csr []byte, err error) {
	pk, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	csr, err = util.MakeCSR(pk, spiffeID)
	if err != nil {
		return nil, nil, err
	}
	return
}

func (m *manager) bundleAlreadyCached(bundle []*x509.Certificate) bool {
	currentBundle := m.cache.Bundle()

	if currentBundle == nil {
		return bundle == nil
	}

	if len(bundle) != len(currentBundle) {
		return false
	}

	for i, cert := range currentBundle {
		if !cert.Equal(bundle[i]) {
			return false
		}
	}

	return true
}

// entryRequest holds a CSR and a pre-built cache entry for the RegistrationEntry
// contained in the entry field.
type entryRequest struct {
	CSR   []byte
	entry *cache.Entry
}

// entryRequests is a map keyed by Registration Entry ID of entryRequest that
// should be processed using the SVID and PrivateKey created for it.
type entryRequests map[string]*entryRequest

func (er entryRequests) add(e *entryRequest) {
	entryID := e.entry.RegistrationEntry.EntryId
	er[entryID] = e
}

func (er entryRequests) truncate(limit int) {
	counter := 1
	for id := range er {
		if counter > limit {
			delete(er, id)
		}

		counter++
	}
}
