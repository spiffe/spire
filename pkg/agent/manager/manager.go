package manager

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/proto/common"

	tomb "gopkg.in/tomb.v2"
)

// Cache Manager errors
var (
	ErrNotCached         = errors.New("bundle not cached")
	ErrPartialResponse   = errors.New("partial response received")
	ErrUnableToGetStream = errors.New("unable to get a stream")
)

// Manager provides cache management functionalities for agents.
type Manager interface {
	// Start starts the manager. It blocks until fully initialized.
	Start() error

	// Shutdown blocks until the manager stops.
	Shutdown()

	// Subscribe returns a channel on which cache entry updates are sent
	// for a particular set of selectors.
	Subscribe(key cache.Selectors, done chan struct{}) chan *cache.WorkloadUpdate

	// MatchingEntries takes a slice of selectors, and iterates over all the in force entries
	// in order to find matching cache entries. A cache entry is matched when its RegistrationEntry's
	// selectors are included in the set of selectors passed as parameter.
	MatchingEntries(selectors []*common.Selector) []*cache.Entry

	// Stopped returns a channel on which the receiver can block until
	// the manager stops running.
	Stopped() <-chan struct{}

	// Err returns the reason why the manager stopped running. If this returns
	// nil, then the manager was stopped externally by calling its Shutdown() method.
	Err() error
}

type manager struct {
	c     *Config
	t     *tomb.Tomb
	cache cache.Cache

	// Fields protected by mtx mutex.
	mtx     *sync.RWMutex
	svid    *x509.Certificate
	svidKey *ecdsa.PrivateKey

	spiffeID       string
	serverSPIFFEID string
	serverAddr     *net.TCPAddr

	svidCachePath   string
	bundleCachePath string

	syncClients *clientsPool
}

func (m *manager) Start() error {
	err := m.storeSVID()
	if err != nil {
		m.c.Log.Warnf("Could not write SVID to %v: %v", m.svidCachePath, err)
	}

	err = m.synchronize(m.spiffeID)
	if err != nil {
		m.close(err)
		return err
	}

	m.t.Go(m.run)

	go func() {
		err := m.t.Wait()
		m.close(err)
	}()
	return nil
}

func (m *manager) close(err error) {
	m.syncClients.close()
	if err != nil {
		m.c.Log.Errorf("cache manager crashed: %v", err)
	} else {
		m.c.Log.Info("Cache manager stopped")
	}
}

func (m *manager) Shutdown() {
	m.shutdown(nil)
	<-m.t.Dead()
}

func (m *manager) Subscribe(selectors cache.Selectors, done chan struct{}) chan *cache.WorkloadUpdate {
	// creates a subscriber
	// adds it to the manager
	// returns the added subscriber channel
	sub, err := cache.NewSubscriber(selectors, done)
	if err != nil {
		m.c.Log.Warning(err)

	}
	m.cache.Subscribe(sub)

	return sub.C
}

func (m *manager) MatchingEntries(selectors []*common.Selector) (entries []*cache.Entry) {
	for _, entry := range m.cache.Entries() {
		regEntrySelectors := selector.NewSetFromRaw(entry.RegistrationEntry.Selectors)
		if selector.NewSetFromRaw(selectors).IncludesSet(regEntrySelectors) {
			entries = append(entries, entry)
		}
	}
	return entries
}

func (m *manager) Stopped() <-chan struct{} {
	return m.t.Dead()
}

func (m *manager) Err() error {
	return m.t.Err()
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
			err := m.synchronize(m.spiffeID)
			if err != nil {
				// Just log the error to keep waiting for next sinchronization...
				m.c.Log.Errorf("synchronize failed: %v", err)
			}
		case <-m.t.Dying():
			return nil
		}
	}
}

func (m *manager) rotator() error {
	t := time.NewTicker(1 * time.Minute)

	for {
		select {
		case <-t.C:
			err := m.rotateSVID()
			if err != nil {
				// Just log the error to keep waiting for next SVID rotation...
				m.c.Log.Errorf("SVID rotation failed: %v", err)
			}
		case <-m.t.Dying():
			return nil
		}
	}
}

func (m *manager) shutdown(err error) {
	m.t.Kill(err)
}

func (m *manager) isAlreadyCached(regEntry *common.RegistrationEntry) bool {
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
	certPool := x509.NewCertPool()
	for _, cert := range m.cache.Bundle() {
		certPool.AddCert(cert)
	}
	return certPool
}

func (m *manager) setBundle(bundle []*x509.Certificate) {
	m.cache.SetBundle(bundle)
	m.storeBundle()
}
