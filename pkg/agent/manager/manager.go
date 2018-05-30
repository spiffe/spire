package manager

import (
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/imkira/go-observer"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/svid"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/proto/common"

	tomb "gopkg.in/tomb.v2"
)

// Cache Manager errors
var (
	ErrNotCached = errors.New("not cached")
)

// Manager provides cache management functionalities for agents.
type Manager interface {
	// Start starts the manager. It blocks until fully initialized.
	Start() error

	// Shutdown blocks until the manager stops.
	Shutdown()

	// SubscribeToCacheChanges returns a Subscriber on which cache entry updates are sent
	// for a particular set of selectors.
	SubscribeToCacheChanges(key cache.Selectors) cache.Subscriber

	// SubscribeToSVIDChanges returns a new observer.Stream on which svid.State instances are received
	// each time an SVID rotation finishes.
	SubscribeToSVIDChanges() observer.Stream

	// SubscribeToBundleChanges returns a new observer.Stream on which []*x509.Certificate instances are
	// received each time the bundle changes.
	SubscribeToBundleChanges() observer.Stream

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
	c *Config

	// Fields protected by mtx mutex.
	mtx     *sync.RWMutex
	running bool

	t     *tomb.Tomb
	cache cache.Cache
	svid  svid.Rotator

	spiffeID       string
	serverSPIFFEID string
	serverAddr     net.Addr

	svidCachePath   string
	bundleCachePath string

	syncClients *clientsPool
}

func (m *manager) Start() error {
	m.storeSVID(m.svid.State().SVID)
	m.storeBundle(m.cache.Bundle())

	err := m.synchronize(m.spiffeID)
	if err != nil {
		m.close(err)
		return err
	}

	m.t.Go(m.run)

	go func() {
		err := m.t.Wait()
		m.close(err)
		m.setRunning(false)
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
	if m.isRunning() {
		<-m.t.Dead()
	}
}

func (m *manager) SubscribeToCacheChanges(selectors cache.Selectors) cache.Subscriber {
	return m.cache.Subscribe(selectors)
}

func (m *manager) SubscribeToSVIDChanges() observer.Stream {
	return m.svid.Subscribe()
}

func (m *manager) SubscribeToBundleChanges() observer.Stream {
	return m.cache.SubscribeToBundleChanges()
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
	m.setRunning(true)
	m.t.Go(m.synchronizer)
	m.t.Go(m.startSVIDObserver)
	m.t.Go(m.startBundleObserver)
	m.svid.Start()
	return nil
}

func (m *manager) synchronizer() error {
	t := time.NewTicker(m.c.SyncInterval)
	defer t.Stop()

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

func (m *manager) startSVIDObserver() error {
	svidStream := m.SubscribeToSVIDChanges()
	for {
		select {
		case <-m.t.Dying():
			return nil
		case <-svidStream.Changes():
			s := svidStream.Next().(svid.State)
			m.storeSVID(s.SVID)
		}
	}
}

func (m *manager) startBundleObserver() error {
	bundleStream := m.SubscribeToBundleChanges()
	for {
		select {
		case <-m.t.Dying():
			return nil
		case <-bundleStream.Changes():
			b := bundleStream.Next().([]*x509.Certificate)
			m.storeBundle(b)
		}
	}
}

func (m *manager) shutdown(err error) {
	m.svid.Stop()
	m.t.Kill(err)
}

func (m *manager) isRunning() bool {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	return m.running
}

func (m *manager) setRunning(value bool) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.running = value
}

func (m *manager) isAlreadyCached(regEntry *common.RegistrationEntry) bool {
	return m.cache.Entry(regEntry) != nil
}

func (m *manager) storeSVID(svid *x509.Certificate) {
	err := StoreSVID(m.svidCachePath, svid)
	if err != nil {
		m.c.Log.Warnf("could not store SVID: %v", err)
	}
}

func (m *manager) storeBundle(bundle []*x509.Certificate) {
	err := StoreBundle(m.bundleCachePath, bundle)
	if err != nil {
		m.c.Log.Errorf("could not store bundle: %v", err)
	}
}
