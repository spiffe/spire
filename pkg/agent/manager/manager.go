package manager

import (
	"errors"

	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/proto/common"
)

// Cache Manager errors
var (
	ErrNotCached       = errors.New("bundle not cached")
	ErrPartialResponse = errors.New("partial response received")
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
	MatchingEntries(selectors []*common.Selector) []cache.Entry

	// Stopped returns a channel on which the receiver can block until
	// the manager stops running.
	Stopped() chan struct{}

	// Err returns the reason why the manager stopped running. If this returns
	// nil, then the manager was stopped externally by calling its Shutdown() method.
	Err() error
}

func (m *manager) Start() error {
	err := m.synchronize()
	if err != nil {
		return err
	}

	m.t.Go(m.run)

	go func() {
		err := m.t.Wait()
		m.syncClients.close()
		if err != nil {
			m.err = err
			m.c.Log.Errorf("Cache Manager crashed: %v", err)
		} else {
			m.c.Log.Info("Cache Manager stopped gracefully")
		}
		close(m.stopped)
	}()
	return nil
}

func (m *manager) Shutdown() {
	m.shutdown(nil)
	<-m.stopped
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

func (m *manager) MatchingEntries(selectors []*common.Selector) (entries []cache.Entry) {
	for entry := range m.cache.Entries() {
		regEntrySelectors := selector.NewSetFromRaw(entry.RegistrationEntry.Selectors)
		if selector.NewSetFromRaw(selectors).IncludesSet(regEntrySelectors) {
			entries = append(entries, entry)
		}
	}
	return entries
}

func (m *manager) Stopped() chan struct{} {
	return m.stopped
}

func (m *manager) Err() error {
	return m.err
}
