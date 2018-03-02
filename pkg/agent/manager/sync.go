package manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	proto "github.com/spiffe/spire/proto/common"
)

// synchronize hits the node api, checks for entries we haven't fetched yet, and fetches them.
func (m *manager) synchronize() (err error) {
	m.c.Log.Debug("synchronize started")
	defer m.c.Log.Debug("synchronize finished")

	var regEntries map[string]*proto.RegistrationEntry
	var cEntryRequests entryRequests
	for spiffeId, _ := range m.syncClients.clients {
		regEntries, _, err = m.fetchUpdates(spiffeId, nil)
		if err != nil {
			return err
		}

		cEntryRequests, err = m.checkExpiredCacheEntries()
		if err != nil {
			return err
		}

		// While there are registration entries or cache entries to process...
		for len(regEntries) > 0 || len(cEntryRequests) > 0 {
			cEntryRequests, err = m.checkForNewCacheEntries(regEntries, cEntryRequests)
			if err != nil {
				return err
			}

			regEntries, err = m.processEntryRequests(cEntryRequests)
			if err != nil {
				return err
			}
			cEntryRequests = entryRequests{}
		}
	}

	return nil
}

// entryRequest holds a CSR and a pre-built cache entry for the RegistrationEntry
// contained in the entry field.
type entryRequest struct {
	CSR   []byte
	entry *cache.Entry
}

// entryRequests is a map keyed by SPIFFEID where each value is a list
// of entryRequest that should be processed using the SVID and PrivateKey
// created for it.
type entryRequests map[string][]*entryRequest

func (m *manager) fetchUpdates(spiffeID string, entryRequests []*entryRequest) (map[string]*common.RegistrationEntry, map[string]*node.Svid, error) {
	m.c.Log.Debugf("fetchUpdates started using SVID and key for spiffeID: %s", spiffeID)
	defer m.c.Log.Debug("fetchUpdates finished")

	client := m.syncClients.get(spiffeID)
	if client == nil {
		return nil, nil, fmt.Errorf("No client found for %s", spiffeID)
	}

	// Put all the CSRs in an array to make just one call with all the CSRs.
	csrs := [][]byte{}
	if entryRequests != nil {
		for _, entryRequest := range entryRequests {
			csrs = append(csrs, entryRequest.CSR)
		}
	}

	update, err := client.sendAndReceive(&node.FetchSVIDRequest{Csrs: csrs})
	if err != nil && err != ErrPartialResponse {
		return nil, nil, err
	}

	m.c.Log.Debugf("update received: %s", update)

	if update.lastBundle != nil {
		bundle, err := x509.ParseCertificates(update.lastBundle)
		if err != nil {
			return nil, nil, err
		}
		m.setBundle(bundle)
	}

	return update.regEntries, update.svids, nil
}

func (m *manager) processEntryRequests(entryRequests entryRequests) (map[string]*common.RegistrationEntry, error) {
	m.c.Log.Debug("processEntryRequests started")
	defer m.c.Log.Debug("processEntryRequests finished")

	regEntries := map[string]*common.RegistrationEntry{}
	if len(entryRequests) == 0 {
		return regEntries, nil
	}

	for parentID, entryRequestsList := range entryRequests {
		re, svids, err := m.fetchUpdates(parentID, entryRequestsList)
		if err != nil {
			return nil, err
		}
		err = m.updateEntriesSVIDs(entryRequestsList, svids)
		if err != nil {
			return nil, err
		}
		// Collect registrations entries.
		for k, e := range re {
			regEntries[k] = e
		}
	}
	return regEntries, nil
}

func (m *manager) updateEntriesSVIDs(entryRequestsList []*entryRequest, svids map[string]*node.Svid) error {
	for _, entryRequest := range entryRequestsList {
		ce := entryRequest.entry
		svid, ok := svids[ce.RegistrationEntry.SpiffeId]
		if ok {
			cert, err := x509.ParseCertificate(svid.SvidCert)
			if err != nil {
				return err
			}
			// Complete the pre-built cache entry with the SVID and put it on the cache.
			ce.SVID = cert
			if m.isAgentAlias(ce.RegistrationEntry) {
				m.c.Log.Debugf("agent alias detected: %s", ce.RegistrationEntry.SpiffeId)

				ce.IsAgentAlias = true
				err := m.newSyncClient([]string{ce.RegistrationEntry.SpiffeId}, ce.SVID, ce.PrivateKey)
				if err != nil {
					return err
				}
			}
			m.cache.SetEntry(ce)
			m.c.Log.Debugf("Updated CacheEntry for SPIFFEId: %s", ce.RegistrationEntry.SpiffeId)
		}
	}
	return nil
}

func (m *manager) checkExpiredCacheEntries() (entryRequests, error) {
	m.c.Log.Debug("checkExpiredCacheEntries started")
	defer m.c.Log.Debug("checkExpiredCacheEntries finished")

	entryRequests := entryRequests{}
	for entry := range m.cache.Entries() {
		ttl := entry.SVID.NotAfter.Sub(time.Now())
		lifetime := entry.SVID.NotAfter.Sub(entry.SVID.NotBefore)
		// If the cached SVID has a remaining lifetime less than 50%, prepare a
		// new entryRequest to ask for a new cache entry to be used in the future
		// when this entry expires.
		if ttl < lifetime/2 {
			privateKey, csr, err := m.newCSR(entry.RegistrationEntry.SpiffeId)
			if err != nil {
				return nil, err
			}

			bundles := make(map[string][]byte) //TODO: walmav Populate Bundles
			cacheEntry := &cache.Entry{
				RegistrationEntry: entry.RegistrationEntry,
				SVID:              nil,
				PrivateKey:        privateKey,
				Bundles:           bundles,
			}
			parentID := entry.RegistrationEntry.ParentId
			entryRequests[parentID] = append(entryRequests[parentID], &entryRequest{csr, cacheEntry})
		} else if ttl <= 0 {
			// Cached SVID expired, remove entry from the cache.
			m.cache.DeleteEntry(entry.RegistrationEntry)
		}
	}
	return entryRequests, nil
}

func (m *manager) checkForNewCacheEntries(regEntries map[string]*proto.RegistrationEntry, entryRequests entryRequests) (entryRequests, error) {
	m.c.Log.Debug("checkForNewCacheEntries started")
	defer m.c.Log.Debug("checkForNewCacheEntries finished")

	for _, regEntry := range regEntries {
		if !m.isAlreadyCached(regEntry) {
			m.c.Log.Debugf("Generating CSR for spiffeId: %s  parentId: %s", regEntry.SpiffeId, regEntry.ParentId)

			privateKey, csr, err := m.newCSR(regEntry.SpiffeId)
			if err != nil {
				return nil, err
			}

			bundles := make(map[string][]byte) //TODO: walmav Populate Bundles
			cacheEntry := &cache.Entry{
				RegistrationEntry: regEntry,
				SVID:              nil,
				PrivateKey:        privateKey,
				Bundles:           bundles,
			}
			parentID := regEntry.ParentId
			entryRequests[parentID] = append(entryRequests[parentID], &entryRequest{csr, cacheEntry})
		} else {
			m.c.Log.Debugf("cache hit for spiffeId: %s, parentId: %s, selectors: %v", regEntry.SpiffeId, regEntry.ParentId, regEntry.Selectors)
		}
	}

	return entryRequests, nil
}

func (m *manager) rotateSVID() error {
	m.c.Log.Debug("rotateSVID started")
	defer m.c.Log.Debug("rotateSVID finished")

	svid, _ := m.getBaseSVIDEntry()
	ttl := svid.NotAfter.Sub(time.Now())
	lifetime := svid.NotAfter.Sub(svid.NotBefore)

	if ttl < lifetime/2 {
		m.c.Log.Debug("Generating new CSR for BaseSVID")

		privateKey, csr, err := m.newCSR(m.spiffeID)
		if err != nil {
			return err
		}

		client := m.getRotationClient()

		m.c.Log.Debug("Sending CSR")

		update, err := client.sendAndReceive(&node.FetchSVIDRequest{Csrs: [][]byte{csr}})
		if err != nil && err != ErrPartialResponse {
			return err
		}

		if len(update.svids) == 0 {
			return errors.New("No SVID received when rotating BaseSVID")
		}

		svid, ok := update.svids[m.spiffeID]
		if !ok {
			return errors.New("It was not possible to get base SVID from FetchSVID response")
		}
		cert, err := x509.ParseCertificate(svid.SvidCert)
		if err != nil {
			return err
		}

		m.c.Log.Debug("Updating manager with new BaseSVID")
		m.setBaseSVIDEntry(cert, privateKey)
		err = m.storeSVID()
		if err != nil {
			return err
		}

		err = m.renewRotatorClient()
		if err != nil {
			return fmt.Errorf("Could not renew rotator client: %v", err)
		}
	}
	return nil
}

func (m *manager) newCSR(spiffeID string) (pk *ecdsa.PrivateKey, csr []byte, err error) {
	pk, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return
	}
	csr, err = util.MakeCSR(pk, spiffeID)
	if err != nil {
		return nil, nil, err
	}
	return
}

func (m *manager) isAgentAlias(re *common.RegistrationEntry) bool {
	if re.ParentId == m.serverSPIFFEID {
		return true
	}

	for _, s := range re.Selectors {
		if s.Type == "spiffe_id" && s.Value == m.spiffeID {
			return true
		}
	}

	return false
}
