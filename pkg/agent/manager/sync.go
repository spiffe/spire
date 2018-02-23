package manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
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
	entryRequests := []*entryRequest{}
	// If cache is empty we need to make the first fetchUpdate without any CSRs.
	if m.cache.IsEmpty() {
		regEntries, _ = m.fetchUpdate(nil)
	} else {
		entryRequests, err = m.checkExpiredCacheEntries()
		if err != nil {
			return err
		}

		regEntries = m.processEntryRequests(entryRequests)
	}

	// While there are registration entries to process...
	for regEntries != nil && len(regEntries) > 0 {
		entryRequests, err := m.checkForNewEntries(regEntries)
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

func (m *manager) processEntryRequests(entryRequests []*entryRequest) (regEntries map[string]*common.RegistrationEntry) {
	// Put all the CSRs in an array to make just one fetchUpdate call with all the CSRs.
	csrs := [][]byte{}
	for _, entryRequest := range entryRequests {
		csrs = append(csrs, entryRequest.CSR)
	}
	if len(csrs) > 0 {
		// Fetch updates for the specified CSRs to get the corresponding SVIDs.
		var svids map[string]*node.Svid
		regEntries, svids = m.fetchUpdate(csrs)
		for _, entryRequest := range entryRequests {
			svid, ok := svids[entryRequest.entry.RegistrationEntry.SpiffeId]
			if ok {
				cert, err := x509.ParseCertificate(svid.SvidCert)
				if err != nil {
					m.shutdown(err)
					return
				}
				// Complete the pre-built cache entry with the SVID and put it on the cache.
				entryRequest.entry.SVID = cert
				if m.isNodeType(entryRequest) {
					entryRequest.entry.IsNodeType = true
					m.addToConnPoolEntry(entryRequest.entry.SVID, entryRequest.entry.PrivateKey)
				}
				m.cache.SetEntry(entryRequest.entry)
				m.subscribers.Notify(entryRequest.entry)
				m.c.Log.Debugf("Updated CacheEntry for SPIFFEId: %s", entryRequest.entry.RegistrationEntry.SpiffeId)
			}
		}
	}
	return
}

func (m *manager) checkExpiredCacheEntries() ([]*entryRequest, error) {
	entryRequests := []*entryRequest{}
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
			entryRequests = append(entryRequests, &entryRequest{csr, cacheEntry})
		} else if ttl <= 0 {
			// Cached SVID expired, remove entry from the cache.
			m.cache.DeleteEntry(entry.RegistrationEntry)
		}
	}

	/*
		vanityRecord := m.cache.Entry([]*proto.Selector{{
			Type: "spiffe_id", Value: m.spiffeID}})

		if vanityRecord != nil {
			m.fetchWithEmptyCSR(vanityRecord[0].SVID, vanityRecord[0].PrivateKey)
		} else {
			baseEntry := m.getBaseSVIDEntry()
			m.fetchWithEmptyCSR(baseEntry.svid, baseEntry.key)
		}

		entry, ok := m.spiffeIdEntryMap[m.aliasSPIFFEID]
		if ok {
			m.fetchWithEmptyCSR(entry.SVID, entry.PrivateKey)
		}
	*/
	return entryRequests, nil
}

func (m *manager) checkForNewEntries(regEntries map[string]*proto.RegistrationEntry) ([]*entryRequest, error) {
	entryRequests := []*entryRequest{}
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
			entryRequests = append(entryRequests, &entryRequest{csr, cacheEntry})
		}
	}

	return entryRequests, nil
}

func (m *manager) rotateSVID() error {
	svid, key := m.getBaseSVIDEntry()

	ttl := svid.NotAfter.Sub(time.Now())
	lifetime := svid.NotAfter.Sub(svid.NotBefore)

	if ttl < lifetime/2 {
		m.c.Log.Debug("Generating new CSR for BaseSVID")

		privateKey, csr, err := m.newCSR(m.spiffeID)
		if err != nil {
			return err
		}

		conn, err := m.newGRPCConn(svid, key)
		if err != nil {
			return err
		}

		// TODO: Should we use FecthBaseSVID instead?
		stream, err := node.NewNodeClient(conn).FetchSVID(context.Background())
		if err != nil {
			return err
		}

		m.c.Log.Debug("Sending CSR")
		err = stream.Send(&node.FetchSVIDRequest{Csrs: [][]byte{csr}})
		if err != nil {
			stream.CloseSend()
			return err
		}
		stream.CloseSend()

		resp, err := stream.Recv()
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

func (m *manager) isNodeType(er *entryRequest) bool {

	if er.entry.RegistrationEntry.ParentId == m.serverSPIFFEID {
		return true
	}

	for _, s := range er.entry.RegistrationEntry.Selectors {
		if s.Type == "spiffe_id" && s.Value == m.spiffeID {
			return true
		}
	}

	return false

}

func (m *manager) addToConnPoolEntry(svid *x509.Certificate, pkey *ecdsa.PrivateKey) error {
	conn, err := m.newGRPCConn(svid, pkey)
	if err != nil {
		return err
	}
	m.agentConnPool = append(m.agentConnPool, conn)
	return nil
}
