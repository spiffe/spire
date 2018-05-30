package manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"time"

	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	proto "github.com/spiffe/spire/proto/common"
)

// synchronize hits the node api, checks for entries we haven't fetched yet, and fetches them.
func (m *manager) synchronize(spiffeID string) (err error) {
	var regEntries map[string]*proto.RegistrationEntry
	var cEntryRequests = entryRequests{}

	regEntries, _, err = m.fetchUpdates(spiffeID, nil)
	if err != nil {
		return err
	}

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

func (m *manager) fetchUpdates(spiffeID string, entryRequests map[string]*entryRequest) (map[string]*common.RegistrationEntry, map[string]*node.Svid, error) {
	// Ensure that we have a client connected to the server.
	client, err := m.ensureSyncClient(spiffeID)
	if err != nil {
		return nil, nil, err
	}

	// Put all the CSRs in an array to make just one call with all the CSRs.
	csrs := [][]byte{}
	if entryRequests != nil {
		for _, entryRequest := range entryRequests {
			m.c.Log.Debugf("Requesting SVID for %v", entryRequest.entry.RegistrationEntry.SpiffeId)
			csrs = append(csrs, entryRequest.CSR)
		}
	}

	update, err := client.FetchUpdates(&node.FetchSVIDRequest{Csrs: csrs})
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

	// Array of aliases that should be synchronized
	aliases := &[]*cache.Entry{}
	for parentID, entryRequestsMap := range entryRequests {
		_, svids, err := m.fetchUpdates(parentID, entryRequestsMap)
		if err != nil {
			return err
		}
		err = m.updateEntriesSVIDs(entryRequestsMap, svids, aliases)
		if err != nil {
			return err
		}
	}

	// For each alias we must synchronize updates on behalf of it.
	for _, alias := range *aliases {
		// Create a new client to be used when checking for new entries on behalf of this
		// agent's alias.
		cfg := &client.Config{
			TrustDomain: m.c.TrustDomain,
			Log:         m.c.Log,
			Addr:        m.c.ServerAddr,
			KeysAndBundle: func() (*x509.Certificate, *ecdsa.PrivateKey, []*x509.Certificate) {
				return alias.SVID, alias.PrivateKey, m.cache.Bundle()
			},
		}
		client := client.New(cfg)
		err := m.addClient(client, alias.RegistrationEntry.SpiffeId)
		if err != nil {
			return err
		}

		err = m.synchronize(alias.RegistrationEntry.SpiffeId)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *manager) updateEntriesSVIDs(entryRequestsMap map[string]*entryRequest, svids map[string]*node.Svid, aliases *[]*cache.Entry) error {
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
			// This entry is an agent alias, collect it
			if m.isAgentAlias(ce.RegistrationEntry) {
				m.c.Log.Debugf("Agent alias detected: %s", ce.RegistrationEntry.SpiffeId)
				*aliases = append(*aliases, ce)
			}
		}
	}
	return nil
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
		} else if m.isAgentAlias(regEntry) {
			// Entry is already cached and is an alias, so we have to check if there are new entries for it.
			re, _, err := m.fetchUpdates(regEntry.SpiffeId, nil)
			if err != nil {
				return err
			}

			err = m.checkForNewCacheEntries(re, cEntryRequests)
			if err != nil {
				return err
			}
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

// entryRequests is a map keyed by Parent SPIFFEID where each value is another map
// (keyed by Registration Entry ID) of entryRequest that should be processed using
// the SVID and PrivateKey created for it.
type entryRequests map[string]map[string]*entryRequest

func (er entryRequests) add(e *entryRequest) {
	parentID := e.entry.RegistrationEntry.ParentId
	entryID := e.entry.RegistrationEntry.EntryId
	erMap, ok := er[parentID]
	if !ok {
		erMap = map[string]*entryRequest{}
		er[parentID] = erMap
	}
	erMap[entryID] = e
}
