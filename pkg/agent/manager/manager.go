package manager

import (
	"crypto/ecdsa"
	"crypto/x509"
	"sync"

	"github.com/spiffe/spire/pkg/agent/manager/cache"

	tomb "gopkg.in/tomb.v2"
)

type Manager interface {
	// Start starts the manager. It blocks until fully initialized.
	Start() error

	// Wait blocks until the manager encounters an error or is shut down.
	Wait() error

	// Shutdown stops the manager.
	Shutdown()

	// Subscribe returns a channel on which cache entry updates are sent
	// for a particular set of selectors.
	Subscribe(key cache.Selectors, done chan struct{}) chan []cache.Entry
}

type manager struct {
	c   *Config
	t   *tomb.Tomb
	mtx *sync.RWMutex

	cache   cache.Cache
	svid    *x509.Certificate
	svidKey *ecdsa.PrivateKey

	subscribers subscribers
}

func (m *manager) Start() error {
	err := m.synchronize()
	if err != nil {
		return err
	}

	m.t.Go(run)
	return nil
}

func (m *manager) Wait() error {
	return m.t.Wait()
}

func (m *manager) Shutdown() {
	m.t.Kill(nil)
}

func (m *manager) Subscribe(key cache.Selectors, done chan struct{}) chan []cache.Entry {
	// TODO
}

func (m *manager) run() error {
	m.t.Go(synchronizer)
	m.t.Go(rotator)
}

// TODO
func (m *manager) synchronizer() error {
	t := time.NewTicker(5 * time.Second)
}

// TODO
func (m *manager) rotator() error {
	t := time.NewTicker(1 * time.Minute)
}

// synchronize hits the node api, checks for entries we haven't fetched yet, and fetches them.
func (m *manager) synchronize() error {
	// TODO
}

func (m *manager) newCSR(id url.URL) error {
	// TODO
}
