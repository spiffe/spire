package manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io"
	"net"
	"sync"
	"time"

	spiffe_tls "github.com/spiffe/go-spiffe/tls"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	proto "github.com/spiffe/spire/proto/common"
	tomb "gopkg.in/tomb.v2"
)

// Cache Manager errors
var (
	ErrNotCached = errors.New("bundle not cached")
)

// Manager provides cache management functionalities for agents.
type Manager interface {
	// Start starts the manager. It blocks until fully initialized.
	Start() error

	// Shutdown stops the manager.
	Shutdown()

	// Subscribe returns a channel on which cache entry updates are sent
	// for a particular set of selectors.
	Subscribe(key cache.Selectors, done chan struct{}) chan []cache.Entry

	// Stopped returns a channel on which the receiver can block until it
	// get the reason of why the manager stopped running.
	Stopped() chan error
}

type manager struct {
	c     *Config
	t     *tomb.Tomb
	cache cache.Cache

	fetchSVIDStream node.Node_FetchSVIDClient

	stopped chan error

	// Fields protected by mtx mutex.
	mtx     *sync.RWMutex
	svid    *x509.Certificate
	svidKey *ecdsa.PrivateKey
	bundle  []*x509.Certificate // Latest CA bundle

	spiffeID       string
	serverSPIFFEID string
	serverAddr     *net.TCPAddr

	svidCachePath   string
	bundleCachePath string

	subscribers subscribers
}

func (m *manager) Start() error {
	err := m.initialize()
	if err != nil {
		return err
	}

	err = m.synchronize()
	if err != nil {
		return err
	}

	m.t.Go(m.run)

	go func() {
		err := m.t.Wait()
		m.c.Log.Info("Cache Manager Stopped")
		if err != nil {
			m.c.Log.Warning(err)
		}
		m.stopped <- err
		close(m.stopped)
	}()
	return nil
}

func (m *manager) Shutdown() {
	m.shutdown(nil)
}

func (m *manager) shutdown(err error) {
	m.t.Kill(err)
}

func (m *manager) Subscribe(key cache.Selectors, done chan struct{}) chan []cache.Entry {
	// TODO
	return nil
}

func (m *manager) Stopped() chan error {
	return m.stopped
}

func (m *manager) run() error {
	m.t.Go(m.synchronizer)
	m.t.Go(m.rotator)
	return nil
}

func (m *manager) initialize() error {
	conn, err := m.newGRPCConn(m.svid, m.svidKey)
	if err != nil {
		return err
	}

	nodeClient := node.NewNodeClient(conn)

	fetchSVIDStream, err := nodeClient.FetchSVID(context.TODO())
	if err != nil {
		return err
	}

	m.fetchSVIDStream = fetchSVIDStream
	return nil
}

// TODO
func (m *manager) synchronizer() error {
	t := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-t.C:
			err := m.synchronize()
			if err != nil {
				return err
			}
		case <-m.t.Dying():
			return nil
		}
	}
}

// TODO
func (m *manager) rotator() error {
	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			err := m.rotateSVID()
			if err != nil {
				return err
			}
		case <-m.t.Dying():
			return nil
		}
	}
}

type entryRequest struct {
	CSR   []byte
	entry cache.Entry
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

// synchronize hits the node api, checks for entries we haven't fetched yet, and fetches them.
func (m *manager) synchronize() error {

	err := m.checkExpiredCacheEntries()
	if err != nil {
		return err
	}

	regEntries, svids, bundle := m.fetchUpdate(nil)

	for len(regEntries) > 0 {
		// Get a map containing the CSR and a pre-built cache entry for each registration entry.
		entryRequestMap, err := m.regEntriesToEntryRequestMap(regEntries)
		if err != nil {
			return err
		}

		// Put all the CSRs in an array.
		csrs := [][]byte{}
		for _, entryRequest := range entryRequestMap {
			csrs = append(csrs, entryRequest.CSR)
		}
		if len(csrs) > 0 {
			// Fetch updates for the specified CSRs to get the corresponding SVIDs.
			regEntries, svids, bundle = m.fetchUpdate(csrs)
			for _, entryRequest := range entryRequestMap {
				svid, ok := svids[entryRequest.entry.RegistrationEntry.SpiffeId]
				if ok {
					cert, err := x509.ParseCertificate(svid.SvidCert)
					if err != nil {
						return err
					}
					// Complete the pre-built cache entry with the SVID and put it on the cache.
					entryRequest.entry.SVID = cert
					m.cache.SetEntry(entryRequest.entry)
					m.c.Log.Debugf("Updated CacheEntry for SPIFFEId: %s", entryRequest.entry.RegistrationEntry.SpiffeId)
				}
			}
		}
	}

	m.setBundle(bundle)
	return nil
}

func (m *manager) regEntriesToEntryRequestMap(regEntries map[string]*proto.RegistrationEntry) (map[string]entryRequest, error) {
	entryRequestMap := make(map[string]entryRequest)
	for key, regEntry := range regEntries {

		/*
			if regEntry.ParentId == m.serverSPIFFEID {
				m.aliasSPIFFEID = regEntry.SpiffeId
			}
		*/

		if !m.isAlreadyCached(regEntry) {
			m.c.Log.Debugf("Generating CSR for spiffeId: %s  parentId: %s", regEntry.SpiffeId, regEntry.ParentId)

			privateKey, csr, err := m.newCSR(regEntry.SpiffeId)
			if err != nil {
				//m.shutdown(err)
				return nil, err
			}

			//parentID := regEntry.ParentId
			bundles := make(map[string][]byte) //TODO: walmav Populate Bundles
			cacheEntry := cache.Entry{
				RegistrationEntry: regEntry,
				SVID:              nil,
				PrivateKey:        privateKey,
				Bundles:           bundles,
			}
			entryRequestMap[key] = entryRequest{csr, cacheEntry}
		}
		// Remove the processed entry from the map
		delete(regEntries, key)
	}

	return entryRequestMap, nil
}

func (m *manager) checkExpiredCacheEntries() error {

	entryRequestMap := make(map[string][]entryRequest)
	for _, entries := range m.cache.Entries() {
		for _, entry := range entries {
			ttl := entry.SVID.NotAfter.Sub(time.Now())
			lifetime := entry.SVID.NotAfter.Sub(entry.SVID.NotBefore)
			// If the cached SVID has a remaining lifetime less than 50%, prepare a
			// new CSR and entryRequest to renew it.
			if ttl < lifetime/2 {
				privateKey, csr, err := m.newCSR(entry.RegistrationEntry.SpiffeId)
				if err != nil {
					return err
				}

				bundles := make(map[string][]byte) //TODO: walmav Populate Bundles
				cacheEntry := cache.Entry{
					RegistrationEntry: regEntry,
					SVID:              nil,
					PrivateKey:        privateKey,
					Bundles:           bundles,
				}
				entryRequestMap[key] = entryRequest{csr, cacheEntry}
				//entry.PrivateKey = privateKey
				//parentID := entry.RegistrationEntry.ParentId
				//entryRequestMap[parentID] = append(entryRequestMap[parentID], entryRequest{csr, entry})
			}
			//spiffeID := entry.RegistrationEntry.SpiffeId
			//m.spiffeIdEntryMap[spiffeID] = entry
		}
	}
	/*
		if len(entryRequestMap) != 0 {
			select {
			case m.entryRequestCh <- entryRequestMap:
			case <-m.ctx.Done():
				m.Shutdown(m.ctx.Err())
				return
			}
		}
	*/

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
	return nil
}

func (m *manager) newGRPCConn(svid *x509.Certificate, key *ecdsa.PrivateKey) (*grpc.ClientConn, error) {
	var tlsCert []tls.Certificate
	var tlsConfig *tls.Config

	spiffePeer := &spiffe_tls.TLSPeer{
		SpiffeIDs:  []string{m.serverSPIFFEID},
		TrustRoots: m.bundleAsCertPool(),
	}
	tlsCert = append(tlsCert, tls.Certificate{Certificate: [][]byte{svid.Raw}, PrivateKey: key})
	tlsConfig = spiffePeer.NewTLSConfig(tlsCert)
	dialCreds := grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))

	conn, err := grpc.Dial(m.serverAddr.String(), dialCreds)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (m *manager) fetchUpdate(csrs [][]byte) (regEntries map[string]*common.RegistrationEntry, svids map[string]*node.Svid, bundle []*x509.Certificate) {
	err := m.fetchSVIDStream.Send(&node.FetchSVIDRequest{Csrs: csrs})
	if err != nil {
		// TODO: should we try to create a new stream?
		m.shutdown(err)
		return
	}

	regEntries = map[string]*common.RegistrationEntry{}
	svids = map[string]*node.Svid{}
	var lastBundle []byte
	for {
		resp, err := m.fetchSVIDStream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			// TODO: should we try to create a new stream?
			m.shutdown(err)
			return nil, nil, nil
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
		bundle, err = x509.ParseCertificates(lastBundle)
		if err != nil {
			m.shutdown(err)
			return nil, nil, nil
		}

	}

	return
}

func (m *manager) getBaseSVIDEntry() (svid *x509.Certificate, key *ecdsa.PrivateKey) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	key = m.svidKey
	svid = m.svid
	return
}

func (m *manager) setBaseSVIDEntry(svid *x509.Certificate, key *ecdsa.PrivateKey) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.svidKey = key
	m.svid = svid
}

func (m *manager) bundleAsCertPool() *x509.CertPool {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	certPool := x509.NewCertPool()
	for _, cert := range m.bundle {
		certPool.AddCert(cert)
	}
	return certPool
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

func (m *manager) isAlreadyCached(regEntry *proto.RegistrationEntry) bool {
	return m.cache.Entry(regEntry.Selectors) != nil
}

func (m *manager) setBundle(bundle []*x509.Certificate) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.bundle = bundle
	m.storeBundle()
}
