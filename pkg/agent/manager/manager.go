package manager

import (
	"errors"

	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/proto/common"
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
	Subscribe(key cache.Selectors, done chan struct{}) chan *cache.Entry

	// MatchingEntries takes a slice of selectors, and iterates over all the in force entries
	// in order to find matching cache entries. A cache entry is matched when its RegistrationEntry's
	// selectors are included in the set of selectors passed as parameter.
	MatchingEntries(selectors []*common.Selector) []cache.Entry

	// Stopped returns a channel on which the receiver can block until it
	// get the reason of why the manager stopped running.
	Stopped() chan error
}

func (m *manager) Start() error {
	err := m.synchronize()
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
		m.syncClients.close()
		m.stopped <- err
		close(m.stopped)
	}()
	return nil
}

func (m *manager) Shutdown() {
	m.shutdown(nil)
}

func (m *manager) Subscribe(selectors cache.Selectors, done chan struct{}) chan *cache.Entry {
	// creates a subscriber
	// adds it to the manager
	// returns the added subscriber channel
	sub := &subscriber{
		c:    make(chan *cache.Entry),
		sel:  selectors,
		done: done,
	}

	if err := m.subscribers.Add(sub); err != nil {
		m.c.Log.Error(err)
		return nil
	}

	return sub.c
}

func (m *manager) MatchingEntries(selectors []*common.Selector) (entries []cache.Entry) {
	for entry := range m.cache.Entries() {
		regEntrySelectors := selector.NewSetFromRaw(entry.RegistrationEntry.Selectors)
		if selector.NewSetFromRaw(selectors).IncludesSet(regEntrySelectors) {
			entries = append(entries, entries[0])
		}
	}
	return entries
}

func (m *manager) Stopped() chan error {
	return m.stopped
}
