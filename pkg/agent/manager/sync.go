package manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/zeebo/errs"
)

// synchronize hits the node api, checks for entries we haven't fetched yet, and fetches them.
func (m *manager) synchronize(ctx context.Context) (err error) {
	var regEntries map[string]*common.RegistrationEntry
	var cEntryRequests = entryRequests{}

	regEntries, _, err = m.fetchUpdates(ctx, nil)
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

	err = m.processEntryRequests(ctx, cEntryRequests)
	if err != nil {
		return err
	}

	return nil
}

func (m *manager) fetchUpdates(ctx context.Context, entryRequests map[string]*entryRequest) (map[string]*common.RegistrationEntry, map[string]*node.X509SVID, error) {
	// Put all the CSRs in an array to make just one call with all the CSRs.
	csrs := [][]byte{}
	if entryRequests != nil {
		for _, entryRequest := range entryRequests {
			m.c.Log.Debugf("Requesting SVID for %v", entryRequest.entry.RegistrationEntry.SpiffeId)
			csrs = append(csrs, entryRequest.CSR)
		}
	}

	update, err := m.client.FetchUpdates(ctx, &node.FetchX509SVIDRequest{Csrs: csrs})
	if err != nil {
		return nil, nil, err
	}

	if update.Bundles != nil {
		bundles, err := parseBundles(update.Bundles)
		if err != nil {
			return nil, nil, err
		}
		m.cache.SetBundles(bundles)
	}

	return update.Entries, update.SVIDs, nil
}

func (m *manager) processEntryRequests(ctx context.Context, entryRequests entryRequests) error {
	if len(entryRequests) == 0 {
		return nil
	}

	// Truncate the number of entry requests we are making if it exceeds the CSR
	// burst limit. The rest of the requests will be made on the next pass
	if len(entryRequests) > node.CSRLimit {
		entryRequests.truncate(node.CSRLimit)
	}

	_, svids, err := m.fetchUpdates(ctx, entryRequests)
	if err != nil {
		return err
	}

	if err := m.updateEntriesSVIDs(entryRequests, svids); err != nil {
		return err
	}

	return nil
}

func (m *manager) updateEntriesSVIDs(entryRequestsMap map[string]*entryRequest, svids map[string]*node.X509SVID) error {
	for _, entryRequest := range entryRequestsMap {
		ce := entryRequest.entry
		svid, ok := svids[ce.RegistrationEntry.SpiffeId]
		if ok {
			certs, err := x509.ParseCertificates(svid.CertChain)
			if err != nil {
				return err
			}
			if len(certs) == 0 {
				return errs.New("no certs in SVID")
			}
			// Complete the pre-built cache entry with the SVID and put it on the cache.
			ce.SVID = certs
			m.cache.SetEntry(ce)
		}
	}
	return nil
}

func (m *manager) clearStaleCacheEntries(regEntries map[string]*common.RegistrationEntry) {
	for _, entry := range m.cache.Entries() {
		if _, ok := regEntries[entry.RegistrationEntry.EntryId]; !ok {
			m.cache.DeleteEntry(entry.RegistrationEntry)
		}
	}
}

func (m *manager) checkExpiredCacheEntries(cEntryRequests entryRequests) error {
	defer m.c.Tel.MeasureSince([]string{"cache_manager", "expiry_check_duration"}, time.Now())

	for _, entry := range m.cache.Entries() {
		ttl := entry.SVID[0].NotAfter.Sub(time.Now())
		lifetime := entry.SVID[0].NotAfter.Sub(entry.SVID[0].NotBefore)
		// If the cached SVID has a remaining lifetime less than 50%, prepare a
		// new entryRequest.
		if ttl < lifetime/2 {
			m.c.Log.Debugf("cache entry ttl for spiffeId %s is less than a half its lifetime", entry.RegistrationEntry.SpiffeId)
			privateKey, csr, err := m.newCSR(entry.RegistrationEntry.SpiffeId)
			if err != nil {
				return err
			}

			cacheEntry := &cache.Entry{
				RegistrationEntry: entry.RegistrationEntry,
				SVID:              nil,
				PrivateKey:        privateKey,
			}
			cEntryRequests.add(&entryRequest{csr, cacheEntry})
		}
	}

	m.c.Tel.AddSample([]string{"cache_manager", "expiring_svids"}, float32(len(cEntryRequests)))
	return nil
}

func (m *manager) checkForNewCacheEntries(regEntries map[string]*common.RegistrationEntry, cEntryRequests entryRequests) error {
	for _, regEntry := range regEntries {
		existingEntry := m.cache.FetchEntry(regEntry.EntryId)
		if existingEntry != nil {
			// entry exists. if the registration entry has changed, then
			// update the cache and move on.
			if !proto.Equal(existingEntry.RegistrationEntry, regEntry) {
				m.cache.SetEntry(&cache.Entry{
					RegistrationEntry: regEntry,
					SVID:              existingEntry.SVID,
					PrivateKey:        existingEntry.PrivateKey,
				})
			}
			continue
		}

		privateKey, csr, err := m.newCSR(regEntry.SpiffeId)
		if err != nil {
			return err
		}

		cacheEntry := &cache.Entry{
			RegistrationEntry: regEntry,
			SVID:              nil,
			PrivateKey:        privateKey,
		}
		cEntryRequests.add(&entryRequest{csr, cacheEntry})
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

func parseBundles(bundles map[string]*common.Bundle) (map[string]*cache.Bundle, error) {
	out := make(map[string]*cache.Bundle)
	for _, bundle := range bundles {
		bundle, err := bundleutil.BundleFromProto(bundle)
		if err != nil {
			return nil, err
		}
		out[bundle.TrustDomainID()] = bundle
	}
	return out, nil
}
