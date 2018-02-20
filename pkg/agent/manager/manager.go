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
	"net/url"
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

type baseSVIDEntry struct {
	svid *x509.Certificate
	key  *ecdsa.PrivateKey
}

type manager struct {
	c     *Config
	t     *tomb.Tomb
	cache cache.Cache

	fetchSVIDStream node.Node_FetchSVIDClient
	svidRequests    chan *node.FetchSVIDRequest
	svidResponses   chan *node.FetchSVIDResponse

	stopped chan error

	// Fields protected by mtx mutex.
	mtx     *sync.RWMutex
	svid    *x509.Certificate
	svidKey *ecdsa.PrivateKey
	bundle  []*x509.Certificate // Latest CA bundle

	regEntriesCh   chan []*proto.RegistrationEntry
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

type entryRequest struct {
	CSR   []byte
	entry cache.Entry
}

// synchronize hits the node api, checks for entries we haven't fetched yet, and fetches them.
func (m *manager) synchronize() error {

	regEntries, svids, bundle := m.fetchUpdate(nil)

	entryRequestMap, err := m.regEntriesToEntryRequestMap(regEntries)
	if err != nil {
		return err
	}

	csrs := [][]byte{}
	for _, entryRequest := range entryRequestMap {
		/*
			parentID := entryRequest.entry.RegistrationEntry.ParentId

			if _, ok := m.spiffeIdEntryMap[parentID]; ok {
				svid = m.spiffeIdEntryMap[parentID].SVID
				key = m.spiffeIdEntryMap[parentID].PrivateKey
			} else if parentID == m.spiffeID || parentID == m.serverSPIFFEID {
				entry := m.getBaseSVIDEntry()
				svid = entry.svid
				key = entry.key
			} else {
				m.c.Log.Warnf("Unknown parent %s... ignoring", parentID)
				continue
			}
		*/
		csrs = append(csrs, entryRequest.CSR)
	}
	if len(csrs) > 0 {
		regEntries, svids, bundle = m.fetchUpdate(csrs)
		for _, entryRequest := range entryRequestMap {
			svid, ok := svids[entryRequest.entry.RegistrationEntry.SpiffeId]
			if ok {
				cert, err := x509.ParseCertificate(svid.SvidCert)
				if err != nil {
					return err
				}
				entryRequest.entry.SVID = cert
				m.cache.SetEntry(entryRequest.entry)
				m.c.Log.Debugf("Updated CacheEntry for SPIFFEId: %s", entryRequest.entry.RegistrationEntry.SpiffeId)
			}
		}
	}

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
			privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
			if err != nil {
				//m.shutdown(err)
				return nil, err
			}

			m.c.Log.Debugf("Generating CSR for spiffeId: %s  parentId: %s", regEntry.SpiffeId, regEntry.ParentId)
			csr, err := util.MakeCSR(privateKey, regEntry.SpiffeId)
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
	}

	return entryRequestMap, nil
}

func (m *manager) newCSR(id url.URL) error {
	// TODO
	return nil
}

// TODO
func (m *manager) synchronizer() error {
	t := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-t.C:
			m.synchronize()
		}
	}
	return nil
}

// TODO
func (m *manager) rotator() error {
	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()

	//defer wg.Done()
	//ticker := time.NewTicker(frequency)

	for {
		select {
		case <-t.C:
			err := m.rotateBaseSVID()
			if err != nil {
				return err
			}
		case <-m.t.Dying():
			m.Shutdown()
			return nil
		}
	}
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

func (m *manager) fetchUpdate(csrs [][]byte) (regEntries map[string]*common.RegistrationEntry, svids map[string]*node.Svid, bundle []byte) {
	err := m.fetchSVIDStream.Send(&node.FetchSVIDRequest{Csrs: csrs})
	if err != nil {
		// TODO: try to create a new stream
		m.shutdown(err)
		return
	}

	regEntries = map[string]*common.RegistrationEntry{}
	svids = map[string]*node.Svid{}
	for {
		resp, err := m.fetchSVIDStream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			m.shutdown(err)
			return
		}

		for _, re := range resp.SvidUpdate.RegistrationEntries {
			regEntryKey := util.DeriveRegEntryhash(re)
			regEntries[regEntryKey] = re
		}
		for spiffeid, svid := range resp.SvidUpdate.Svids {
			svids[spiffeid] = svid
		}
		bundle = resp.SvidUpdate.Bundle
	}

	return
}

func (m *manager) getBaseSVIDEntry() *baseSVIDEntry {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	return &baseSVIDEntry{
		key:  m.svidKey,
		svid: m.svid,
	}
}

func (m *manager) setBaseSVIDEntry(entry *baseSVIDEntry) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.svidKey = entry.key
	m.svid = entry.svid
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

func (m *manager) rotateBaseSVID() error {
	entry := m.getBaseSVIDEntry()

	ttl := entry.svid.NotAfter.Sub(time.Now())
	lifetime := entry.svid.NotAfter.Sub(entry.svid.NotBefore)

	if ttl < lifetime/2 {
		m.c.Log.Debug("Generating new CSR for BaseSVID")

		privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return err
		}

		csr, err := util.MakeCSR(privateKey, m.spiffeID)
		if err != nil {
			return err
		}

		conn, err := m.newGRPCConn(entry.svid, entry.key)
		if err != nil {
			return err
		}

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

		entry := baseSVIDEntry{
			key:  privateKey,
			svid: cert,
		}

		m.c.Log.Debug("Updating manager with new BaseSVID")
		m.setBaseSVIDEntry(&entry)
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
