package manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"net"
	"sync"
	"time"

	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/proto/api/node"
	proto "github.com/spiffe/spire/proto/common"

	tomb "gopkg.in/tomb.v2"
)

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

func (m *manager) run() error {
	m.t.Go(m.synchronizer)
	m.t.Go(m.rotator)
	return nil
}

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

func (m *manager) shutdown(err error) {
	m.t.Kill(err)
}

func (m *manager) isAlreadyCached(regEntry *proto.RegistrationEntry) bool {
	return m.cache.Entry(regEntry) != nil
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

func (m *manager) setBundle(bundle []*x509.Certificate) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.bundle = bundle
	m.storeBundle()
}
