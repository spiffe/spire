package cache

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
	Init()
	Cache() Cache
	//fetchSVID(requests []EntryRequest, nodeClient node.NodeClient, wg *sync.WaitGroup)
	//getGRPCConn(svid []byte, key *ecdsa.PrivateKey) (*grpc.ClientConn, error)
	//expiredCacheEntryHandler(time.Duration, *sync.WaitGroup)
	Shutdown(err error)
	Done() <-chan struct{}
	Err() error
}

type EntryRequest struct {
	CSR   []byte
	entry CacheEntry
}

type MgrConfig struct {
	ServerCerts    []*x509.Certificate
	ServerSPIFFEID string
	ServerAddr     string
	BaseSVID       []byte
	BaseSVIDKey    *ecdsa.PrivateKey
	BaseRegEntries []*proto.RegistrationEntry
	Logger         logrus.FieldLogger
}

type manager struct {
	managedCache     Cache
	serverCerts      []*x509.Certificate
	serverAddr       string
	serverSPIFFEID   string
	reason           error
	entryRequestCh   chan map[string][]EntryRequest
	regEntriesCh     chan []*proto.RegistrationEntry
	cacheEntryCh     chan CacheEntry
	spiffeIdEntryMap map[string]CacheEntry
	baseSVID         []byte
	baseSVIDKey      *ecdsa.PrivateKey
	baseSPIFFEID     string
	baseRegEntries   []*proto.RegistrationEntry
	log              logrus.FieldLogger
	ctx              context.Context
	cancel           context.CancelFunc
	doneCh           chan struct{}
}

func NewManager(ctx context.Context, c *MgrConfig) (Manager, error) {

	cert, err := x509.ParseCertificate(c.BaseSVID)
	if err != nil {
		return nil, err
	}
	basespiffeID, err := uri.GetURINamesFromCertificate(cert)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)

	return &manager{
		managedCache:     NewCache(),
		serverCerts:      c.ServerCerts,
		serverSPIFFEID:   c.ServerSPIFFEID,
		serverAddr:       c.ServerAddr,
		baseSVID:         c.BaseSVID,
		baseSVIDKey:      c.BaseSVIDKey,
		baseSPIFFEID:     basespiffeID[0],
		baseRegEntries:   c.BaseRegEntries,
		log:              c.Logger.WithField("subsystem_name", "cacheManager"),
		spiffeIdEntryMap: make(map[string]CacheEntry),
		entryRequestCh:   make(chan map[string][]EntryRequest),
		regEntriesCh:     make(chan []*proto.RegistrationEntry),
		cacheEntryCh:     make(chan CacheEntry),
		ctx:              ctx,
		cancel:           cancel,
		doneCh:           make(chan struct{}),
	}, nil
}

func (m *manager) Shutdown(err error) {
	m.reason = err
	m.cancel()
}
func (m *manager) Done() <-chan struct{} {
	return m.doneCh
}
func (m *manager) Err() (err error) {
	<-m.Done()
	return m.reason
}
func (m *manager) Cache() Cache {
	return m.managedCache
}

func (m *manager) Init() {
	defer close(m.doneCh)
	var wg sync.WaitGroup
	wg.Add(1)
	go m.expiredCacheEntryHandler(5*time.Second, &wg)

	wg.Add(1)
	go m.regEntriesHandler(&wg)
	m.log.Debug("Initializing Cache Manager", " baseSVIDSPIFFEId:", m.baseSPIFFEID)

	m.regEntriesCh <- m.baseRegEntries

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
					m.Shutdown(err)
				}
				m.log.Debug("Spawning FetchID for", "entryRequests:", entryRequests)
				go m.fetchSVID(entryRequests, node.NewNodeClient(conn), &wg)
			}

		case newCacheEntry := <-m.cacheEntryCh:
			m.log.Debug("Updating Cache ", "entry:", newCacheEntry)
			m.log.Debug("RegistrationEntry:", newCacheEntry.RegistrationEntry.SpiffeId)
			m.managedCache.SetEntry(newCacheEntry)
			m.log.Debug("Updated Cache", "Cache:", newCacheEntry)

		case <-m.ctx.Done():
			m.log.Debug("Stopping cache manager")
			wg.Wait()
			return
		}
	}
}

func (m *manager) fetchSVID(requests []EntryRequest, nodeClient node.NodeClient, wg *sync.WaitGroup) {
	defer wg.Done()
	stream, err := nodeClient.FetchSVID(context.Background())
	if err != nil {
		m.Shutdown(err)
	}
	for _, req := range requests {

		err := stream.Send(&node.FetchSVIDRequest{Csrs: append([][]byte{}, req.CSR)})

		if err != nil {
			m.Shutdown(err)
		}

		resp, err := stream.Recv()
		if err != nil {
			m.Shutdown(err)
		}
		svid := resp.SvidUpdate.Svids[req.entry.RegistrationEntry.SpiffeId]
		cert, err := x509.ParseCertificate(svid.SvidCert)
		if err != nil {
			stream.CloseSend()
			m.Shutdown(err)
		}
		m.log.Debug("Sending to regEntries Channel: ", "entries: ", resp.SvidUpdate.RegistrationEntries)

		m.regEntriesCh <- resp.SvidUpdate.RegistrationEntries
		req.entry.SVID = svid
		req.entry.Expiry = cert.NotAfter
		m.log.Debug("Sending to CacheEntry Channel: ", "req: ", req)
		m.cacheEntryCh <- req.entry

	}
	if err := stream.CloseSend(); err != nil {
		m.Shutdown(err)
	}
	m.log.Debug("Done with fetchSVID")
}

func (m *manager) fetchWithEmptyCSR(svid []byte, key *ecdsa.PrivateKey) {
	conn, err := m.getGRPCConn(svid, key)
	if err != nil {
		m.Shutdown(err)
		return
	}
	stream, err := node.NewNodeClient(conn).FetchSVID(context.Background())
	if err != nil {
		m.Shutdown(err)
		return
	}
	err = stream.Send(&node.FetchSVIDRequest{})
	if err != nil {
		m.Shutdown(err)
		return
	}
	strmch := make(chan struct{})
	go func() {
		for {
			resp, err := stream.Recv()
			//		m.log.Debug("regEntries:", resp.SvidUpdate.RegistrationEntries)
			if err == io.EOF {
				close(strmch)
				m.log.Debug("closing stream")
				return
			}

			if err != nil {
				m.Shutdown(err)
				close(strmch)
				return
			}

			m.regEntriesCh <- resp.SvidUpdate.RegistrationEntries
		}
	}()
	stream.CloseSend()
	<-strmch
}

func (m *manager) expiredCacheEntryHandler(cacheFrequency time.Duration, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(cacheFrequency)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			entryRequestMap := make(map[string][]EntryRequest)
			for _, entries := range m.managedCache.Entries() {
				for _, entry := range entries {
					if entry.Expiry.Sub(time.Now()) < time.Until(entry.Expiry)/2 {
						privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
						if err != nil {
							m.Shutdown(err)
						}
						csr, err := util.MakeCSR(privateKey, entry.RegistrationEntry.SpiffeId)
						entry.PrivateKey = privateKey
						parentID := entry.RegistrationEntry.ParentId
						entryRequestMap[parentID] = append(entryRequestMap[parentID], EntryRequest{csr, entry})
					}
					spiffeID := entry.RegistrationEntry.SpiffeId
					m.spiffeIdEntryMap[spiffeID] = entry
				}
			}
			if len(entryRequestMap) != 0 {
				m.log.Debug("Fetching Expired Entries", "len(entryRequestMap):", len(entryRequestMap), "entryMap", entryRequestMap)
				m.entryRequestCh <- entryRequestMap
			}
			vanityRecord := m.managedCache.Entry([]*proto.Selector{&proto.Selector{Type: "spiffe_id", Value: m.baseSPIFFEID}})

			if vanityRecord != nil {
				m.log.Debug("Fetching new reg Entries for vanity spiffeid:", vanityRecord[0].RegistrationEntry.SpiffeId)
				m.log.Debug("len(entryRequestMap):", len(entryRequestMap))
				m.fetchWithEmptyCSR(vanityRecord[0].SVID.SvidCert, vanityRecord[0].PrivateKey)
			}
			m.log.Debug("Fetching new reg Entries for base spiffeid:", m.baseSPIFFEID)
			m.fetchWithEmptyCSR(m.baseSVID, m.baseSVIDKey)

		case <-m.ctx.Done():
			return
		}
	}
}

func (m *manager) regEntriesHandler(wg *sync.WaitGroup) {
	defer wg.Done()
	processedEntries := make(map[string]*proto.RegistrationEntry)

	for {
		select {
		case regEntries := <-m.regEntriesCh:

			entryRequestMap := make(map[string][]EntryRequest)

			for _, regEntry := range regEntries {
				key := util.DeriveRegEntryhash(regEntry)
				_, processed := processedEntries[key]
				if !processed {
					privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
					if err != nil {
						m.Shutdown(err)
					}
					m.log.Debug("Generating CSR:", " spiffeId:", regEntry.SpiffeId, " parentId:", regEntry.ParentId)
					csr, err := util.MakeCSR(privateKey, regEntry.SpiffeId)
					if err != nil {
						m.Shutdown(err)
					}
					parentID := regEntry.ParentId
					bundles := make(map[string][]byte) //TODO: walmav Populate Bundles
					cacheEntry := CacheEntry{
						RegistrationEntry: regEntry,
						SVID:              nil,
						PrivateKey:        privateKey,
						Bundles:           bundles,
					}
					entryRequestMap[parentID] = append(entryRequestMap[parentID],
						EntryRequest{csr, cacheEntry})

					processedEntries[key] = regEntry

				}

			}
			if len(entryRequestMap) != 0 {
				m.entryRequestCh <- entryRequestMap
			}

		case <-m.ctx.Done():
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
