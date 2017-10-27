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
	once             sync.Once
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
		managedCache:     NewCache(c.Logger),
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
	m.once.Do(func() {
		m.reason = err
	})
	m.cancel()
}

func (m *manager) Done() <-chan struct{} {
	return m.doneCh
}
func (m *manager) Err() error {
	<-m.Done()
	return m.reason
}
func (m *manager) Cache() Cache {
	return m.managedCache
}

func (m *manager) Init() {
	go func() {
		defer close(m.doneCh)
		var wg sync.WaitGroup

		wg.Add(1)
		go m.expiredCacheEntryHandler(5*time.Second, &wg)

		wg.Add(1)
		go m.regEntriesHandler(&wg)
		m.log.Debug("Initializing Cache Manager")
		m.regEntriesCh <- m.baseRegEntries
		for {

			var svid []byte
			var key *ecdsa.PrivateKey
			select {
			case reqs := <-m.entryRequestCh:
				for parentId, entryRequests := range reqs {
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
						break
					}
					wg.Add(1)
					go m.fetchSVID(entryRequests, node.NewNodeClient(conn), &wg)
				}

			case newCacheEntry := <-m.cacheEntryCh:
				m.managedCache.SetEntry(newCacheEntry)
				m.log.Debugf("Updated CacheEntry: %s", newCacheEntry)

			case <-m.ctx.Done():
				wg.Wait()
				return

			}
		}
	}()
}

func (m *manager) fetchSVID(requests []EntryRequest, nodeClient node.NodeClient, wg *sync.WaitGroup) {
	defer wg.Done()
	stream, err := nodeClient.FetchSVID(m.ctx)
	if err != nil {
		m.Shutdown(err)
		return
	}
	defer func() {
		if err := stream.CloseSend(); err != nil {
			m.Shutdown(err)
			return
		}
	}()

	for _, req := range requests {

		err := stream.Send(&node.FetchSVIDRequest{Csrs: append([][]byte{}, req.CSR)})

		if err != nil {
			m.Shutdown(err)
			return
		}

		resp, err := stream.Recv()
		if err != nil {
			m.Shutdown(err)
			return
		}
		svid := resp.SvidUpdate.Svids[req.entry.RegistrationEntry.SpiffeId]
		cert, err := x509.ParseCertificate(svid.SvidCert)
		if err != nil {
			m.Shutdown(err)
			return
		}

		m.regEntriesCh <- resp.SvidUpdate.RegistrationEntries
		req.entry.SVID = svid
		req.entry.Expiry = cert.NotAfter
		select {
		case m.cacheEntryCh <- req.entry:
		case <-m.ctx.Done():
			m.Shutdown(m.ctx.Err())
			return
		}

	}

}

func (m *manager) fetchWithEmptyCSR(svid []byte, key *ecdsa.PrivateKey) {
	conn, err := m.getGRPCConn(svid, key)
	if err != nil {
		m.Shutdown(err)
		return
	}
	stream, err := node.NewNodeClient(conn).FetchSVID(m.ctx)
	if err != nil {
		m.log.Warning(err)
		if stream != nil {
			stream.CloseSend()
		}
		return
	}

	err = stream.Send(&node.FetchSVIDRequest{})
	if err != nil {
		m.Shutdown(err)
		stream.CloseSend()
		return
	}
	stream.CloseSend()

	strmch := make(chan struct{})
	go func() {
		defer close(strmch)
		for {
			resp, err := stream.Recv()
			if err == io.EOF {
				return
			}

			if err != nil {
				m.Shutdown(err)
				return
			}

			select {
			case m.regEntriesCh <- resp.SvidUpdate.RegistrationEntries:
			case <-m.ctx.Done():
				m.Shutdown(m.ctx.Err())
				return
			}
		}
	}()
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
							break
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
				select {
				case m.entryRequestCh <- entryRequestMap:
				case <-m.ctx.Done():
					m.Shutdown(m.ctx.Err())
					return
				}
			}
			vanityRecord := m.managedCache.Entry([]*proto.Selector{{
				Type: "spiffe_id", Value: m.baseSPIFFEID}})

			if vanityRecord != nil {
				m.fetchWithEmptyCSR(vanityRecord[0].SVID.SvidCert, vanityRecord[0].PrivateKey)
			}
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
						break
					}
					m.log.Debugf("Generating CSR for spiffeId: %s  parentId: %s", regEntry.SpiffeId, regEntry.ParentId)
					csr, err := util.MakeCSR(privateKey, regEntry.SpiffeId)
					if err != nil {
						m.Shutdown(err)
						break
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
				select {
				case m.entryRequestCh <- entryRequestMap:
				case <-m.ctx.Done():
					m.Shutdown(m.ctx.Err())
					return
				}
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

	conn, err := grpc.DialContext(m.ctx, m.serverAddr, dialCreds)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
