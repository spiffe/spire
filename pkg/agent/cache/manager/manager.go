package manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"crypto/tls"
	"crypto/x509"
	"github.com/sirupsen/logrus"
	spiffe_tls "github.com/spiffe/go-spiffe/tls"
	"github.com/spiffe/go-spiffe/uri"
	"github.com/spiffe/spire/pkg/agent/cache"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/api/node"
	proto "github.com/spiffe/spire/proto/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io"
	"sync"
	"time"
)

type Manager interface {
	UpdateCache(stop chan struct{})
	fetchSVID(requests []EntryRequest, nodeClient node.NodeClient, wg *sync.WaitGroup)
	getGRPCConn(svid []byte, key *ecdsa.PrivateKey) (*grpc.ClientConn, error)
	expiredCacheEntryHandler(stop chan struct{})
}

type EntryRequest struct {
	CSR   []byte
	entry cache.CacheEntry
}

type manager struct {
	managedCache     cache.Cache
	serverCerts      []*x509.Certificate
	serverAddr       string
	serverSPIFFEID   string
	errorCh          chan error
	entryRequestCh   chan map[string][]EntryRequest
	regEntriesCh     chan []*proto.RegistrationEntry
	CacheEntryCh     chan cache.CacheEntry
	spiffeIdEntryMap map[string]cache.CacheEntry
	baseSVID         []byte
	baseSVIDKey      *ecdsa.PrivateKey
	baseSPIFFEID     string
	regEntries       []*proto.RegistrationEntry
	log              logrus.FieldLogger
}

func NewManager(managedCache cache.Cache,
	serverCerts []*x509.Certificate,
	serverSPIFFEID string,
	serverAddr string,
	errorCh chan error,
	baseSVID []byte, baseSVIDKey *ecdsa.PrivateKey, regEntries []*proto.RegistrationEntry, logger logrus.FieldLogger) manager {
	cert, err := x509.ParseCertificate(baseSVID)
	if err != nil {
		errorCh <- err
	}
	basespiffeID, err := uri.GetURINamesFromCertificate(cert)

	return manager{
		managedCache:   managedCache,
		serverCerts:    serverCerts,
		serverSPIFFEID: serverSPIFFEID,
		serverAddr:     serverAddr,
		baseSVID:       baseSVID,
		baseSVIDKey:    baseSVIDKey,
		baseSPIFFEID:   basespiffeID[0],
		regEntries:     regEntries,
		errorCh:        errorCh,
		log:            logger.WithField("subsystem_name", "cacheManager"),
	}
}

func (m *manager) UpdateCache(stop chan struct{}) {
	m.spiffeIdEntryMap = make(map[string]cache.CacheEntry)
	m.entryRequestCh = make(chan map[string][]EntryRequest)
	m.regEntriesCh = make(chan []*proto.RegistrationEntry)
	m.errorCh = make(chan error)
	m.CacheEntryCh = make(chan cache.CacheEntry)
	stopRequests := make(chan struct{})
	stopRegEntryHandler := make(chan struct{})
	var wg sync.WaitGroup

	go m.expiredCacheEntryHandler(30*time.Second, stopRequests)
	go m.regEntriesHandler(stopRegEntryHandler)
	m.log.Debug("Initializing Cache Manager", " baseSVIDSPIFFEId:", m.baseSPIFFEID)

	m.regEntriesCh <- m.regEntries

	for {

		var svid []byte
		var key *ecdsa.PrivateKey
		select {
		case reqs := <-m.entryRequestCh:
			for parentId, entryRequests := range reqs {
				wg.Add(1)
				if _, ok := m.spiffeIdEntryMap[parentId]; ok {
					svid = m.spiffeIdEntryMap[parentId].SVID.SvidCert
					key = m.spiffeIdEntryMap[parentId].PrivateKey
				}
				if parentId == m.baseSPIFFEID {
					svid = m.baseSVID
					key = m.baseSVIDKey
				}
				conn, err := m.getGRPCConn(svid, key)
				if err != nil {
					m.errorCh <- err
				}
				m.log.Debug("Spawning FetchID for", "entryRequests:", entryRequests)
				go m.fetchSVID(entryRequests, node.NewNodeClient(conn), &wg)
			}

		case newCacheEntry := <-m.CacheEntryCh:
			m.log.Debug("Updating Cache ", "entry:", newCacheEntry)
			m.managedCache.SetEntry(newCacheEntry)
			m.log.Debug("Updated Cache", "Entry:", newCacheEntry)

		case <-stop:
			wg.Wait()
			stopRequests <- struct{}{}
			stopRegEntryHandler <- struct{}{}
			return
		}
	}
}

func (m *manager) fetchSVID(requests []EntryRequest, nodeClient node.NodeClient, wg *sync.WaitGroup) {
	defer wg.Done()
	stream, err := nodeClient.FetchSVID(context.Background())
	if err != nil {
		m.errorCh <- err
	}
	for _, req := range requests {
		err := stream.Send(&node.FetchSVIDRequest{Csrs: append([][]byte{}, req.CSR)})

		if err != nil {
			m.errorCh <- err
		}

		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			m.errorCh <- err
		}
		svid := resp.SvidUpdate.Svids[req.entry.RegistrationEntry.SpiffeId]
		cert, err := x509.ParseCertificate(svid.SvidCert)
		if err != nil {
			m.errorCh <- err
		}
		m.log.Debug("Sending to regEntries Channel: ", "entries: ", resp.SvidUpdate.RegistrationEntries)

		m.regEntriesCh <- resp.SvidUpdate.RegistrationEntries
		req.entry.SVID = svid
		req.entry.Expiry = cert.NotAfter
		m.log.Debug("Sending to CacheEntry Channel: ", "req: ", req)
		m.CacheEntryCh <- req.entry

	}
	m.log.Debug("Done with fetchSVID")
}

func (m *manager) fetchWithEmptyCSR(svid []byte, key *ecdsa.PrivateKey) {
	conn, err := m.getGRPCConn(svid, key)
	if err != nil {
		m.errorCh <- err
	}
	stream, err := node.NewNodeClient(conn).FetchSVID(context.Background())
	if err != nil {
		m.errorCh <- err
	}
	err = stream.Send(&node.FetchSVIDRequest{})
	if err != nil {
		m.errorCh <- err
	}
	for {
		resp, err := stream.Recv()
		m.regEntriesCh <- resp.SvidUpdate.RegistrationEntries
		if err == io.EOF {
			break
		}
		if err != nil {
			m.errorCh <- err
		}
	}

}

func (m *manager) expiredCacheEntryHandler(cacheFrequency time.Duration, stop chan struct{}) {
	ticker := time.Tick(cacheFrequency)

	for {
		select {
		case <-ticker:
			EntryRequestMap := make(map[string][]EntryRequest)
			for _, entries := range m.managedCache.GetEntries() {
				for _, entry := range entries {
					if entry.Expiry.Sub(time.Now()) < time.Until(entry.Expiry)/2 {
						privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
						if err != nil {
							m.errorCh <- err
						}
						csr, err := util.MakeCSR(privateKey, entry.RegistrationEntry.SpiffeId)
						entry.PrivateKey = privateKey
						parentID := entry.RegistrationEntry.ParentId
						EntryRequestMap[parentID] = append(EntryRequestMap[parentID], EntryRequest{csr, entry})
					}
					spiffeID := entry.RegistrationEntry.SpiffeId
					m.spiffeIdEntryMap[spiffeID] = entry
				}
			}
			if len(EntryRequestMap) != 0 {
				m.entryRequestCh <- EntryRequestMap
			}

			vanityRecord := m.managedCache.Entry([]*proto.Selector{&proto.Selector{Type: "spiffe_id", Value: m.baseSPIFFEID}})

			if vanityRecord != nil {
				m.fetchWithEmptyCSR(vanityRecord[0].SVID.SvidCert, vanityRecord[0].PrivateKey)
			}
			m.fetchWithEmptyCSR(m.baseSVID, m.baseSVIDKey)

		case <-stop:
			return
		}
	}
}

func (m *manager) regEntriesHandler(stop chan struct{}) {
	processedEntries := make(map[string]*proto.RegistrationEntry)

	for {
		select {
		case regEntries := <-m.regEntriesCh:

			EntryRequestMap := make(map[string][]EntryRequest)

			for _, regEntry := range regEntries {
				key := util.DeriveRegEntryhash(regEntry)
				_, processed := processedEntries[key]
				if !processed {
					privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
					if err != nil {
						m.errorCh <- err
					}
					m.log.Debug("Generating CSR:", " spiffeId:", regEntry.SpiffeId, " parentId:", regEntry.ParentId)
					csr, err := util.MakeCSR(privateKey, regEntry.SpiffeId)
					parentID := regEntry.ParentId
					bundles := make(map[string][]byte) //TODO: walmav Populate Bundles
					cacheEntry := cache.CacheEntry{
						RegistrationEntry: regEntry,
						SVID:              nil,
						PrivateKey:        privateKey,
						Bundles:           bundles,
					}
					EntryRequestMap[parentID] = append(EntryRequestMap[parentID],
						EntryRequest{csr, cacheEntry})

					processedEntries[key] = regEntry

				}

			}
			if len(EntryRequestMap) != 0 {
				m.entryRequestCh <- EntryRequestMap
			}

		case <-stop:
			return
		}
	}

}

func (m *manager) getGRPCConn(svid []byte, key *ecdsa.PrivateKey) (*grpc.ClientConn, error) {
	var tlsCert []tls.Certificate
	var tlsConfig *tls.Config

	certPool := x509.NewCertPool()
	for _, cert := range m.serverCerts {
		certPool.AddCert(cert)
	}
	spiffePeer := &spiffe_tls.TLSPeer{
		SpiffeIDs:  []string{m.serverSPIFFEID},
		TrustRoots: certPool,
	}
	tlsCert = append(tlsCert, tls.Certificate{Certificate: [][]byte{svid}, PrivateKey: key})
	tlsConfig = spiffePeer.NewTLSConfig(tlsCert)
	dialCreds := grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))

	conn, err := grpc.Dial(m.serverAddr, dialCreds)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
