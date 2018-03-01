package manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
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

	regEntries, _ = m.fetchUpdates(m.spiffeID, nil)

	entryRequests, err := m.checkExpiredCacheEntries()
	if err != nil {
		return err
	}

	// While there are registration entries to process...
	for len(regEntries) > 0 {
		entryRequests, err := m.checkForNewCacheEntries(regEntries, entryRequests)
		if err != nil {
			return err
		}

		regEntries = m.processEntryRequests(entryRequests)
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

func (m *manager) fetchUpdates(spiffeID string, entryRequests []*entryRequest) (regEntries map[string]*common.RegistrationEntry, svids map[string]*node.Svid) {
	regEntries = map[string]*common.RegistrationEntry{}
	svids = map[string]*node.Svid{}
	// TODO: handle error when no client was found.
	client := m.syncClients.get(spiffeID)

	// Put all the CSRs in an array to make just one call with all the CSRs.
	csrs := [][]byte{}
	if entryRequests != nil {
		for _, entryRequest := range entryRequests {
			csrs = append(csrs, entryRequest.CSR)
		}
	}

	err := client.stream.Send(&node.FetchSVIDRequest{Csrs: csrs})
	if err != nil {
		// TODO: should we try to create a new stream?
		m.shutdown(err)
		return
	}

	var lastBundle []byte
	for {
		resp, err := client.stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			// TODO: should we try to create a new stream?
			m.shutdown(err)
			return nil, nil
		}

		for _, re := range resp.SvidUpdate.RegistrationEntries {
			regEntryKey := util.DeriveRegEntryhash(re)
			regEntries[regEntryKey] = re
		}
		for spiffeid, svid := range resp.SvidUpdate.Svids {
			svids[spiffeid] = svid
		}
		lastBundle = resp.SvidUpdate.Bundle
	}

	if lastBundle != nil {
		bundle, err := x509.ParseCertificates(lastBundle)
		if err != nil {
			m.shutdown(err)
			return nil, nil
		}
		m.setBundle(bundle)
	}

	return
}

func (m *manager) processEntryRequests(entryRequests entryRequests) (regEntries map[string]*common.RegistrationEntry) {
	regEntries = map[string]*common.RegistrationEntry{}
	if len(entryRequests) == 0 {
		return
	}

	for parentID, entryRequestsList := range entryRequests {
		re, svids := m.fetchUpdates(parentID, entryRequestsList)
		m.updateEntriesSVIDs(entryRequestsList, svids)
		// Collect registrations entries.
		for k, e := range re {
			regEntries[k] = e
		}
	}
	return
}

func (m *manager) updateEntriesSVIDs(entryRequestsList []*entryRequest, svids map[string]*node.Svid) {
	for _, entryRequest := range entryRequestsList {
		ce := entryRequest.entry
		svid, ok := svids[ce.RegistrationEntry.SpiffeId]
		if ok {
			cert, err := x509.ParseCertificate(svid.SvidCert)
			if err != nil {
				m.shutdown(err)
				return
			}
			// Complete the pre-built cache entry with the SVID and put it on the cache.
			ce.SVID = cert
			if m.isAgentAlias(ce.RegistrationEntry) {
				ce.IsAgentAlias = true
				m.newSyncClient([]string{ce.RegistrationEntry.SpiffeId}, ce.SVID, ce.PrivateKey)
			}
			m.cache.SetEntry(ce)
			m.c.Log.Debugf("Updated CacheEntry for SPIFFEId: %s", ce.RegistrationEntry.SpiffeId)
		}
	}
}

func (m *manager) checkExpiredCacheEntries() (entryRequests, error) {
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
	for _, regEntry := range regEntries {
		if !m.isAlreadyCached(regEntry) {
			m.c.Log.Debugf("Generating CSR for spiffeId: %s  parentId: %s", regEntry.SpiffeId, regEntry.ParentId)

			privateKey, csr, err := m.newCSR(regEntry.SpiffeId)
			if err != nil {
				//m.shutdown(err)
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
		}
	}

	return entryRequests, nil
}

func (m *manager) rotateSVID() error {
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
		err = client.stream.Send(&node.FetchSVIDRequest{Csrs: [][]byte{csr}})
		if err != nil {
			//client.reconnect()
			return err
		}

		resp, err := client.stream.Recv()
		if err == io.EOF {
			return errors.New("FetchSVID stream was empty while trying to rotate BaseSVID")
		}
		if err != nil {
			return err
		}

		svid, ok := resp.SvidUpdate.Svids[m.spiffeID]
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
