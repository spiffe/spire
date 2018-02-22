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
	Subscribe(key cache.Selectors, done chan struct{}) chan []cache.Entry

	// MatchingEntries takes a slice of selectors, and works through all the combinations in order to
	// find matching cache entries.
	MatchingEntries(selectors []*common.Selector) []cache.Entry

	// Stopped returns a channel on which the receiver can block until it
	// get the reason of why the manager stopped running.
	Stopped() chan error
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

func (m *manager) Subscribe(key cache.Selectors, done chan struct{}) chan []cache.Entry {
	// TODO
	return nil
}

// MatchingEntries takes a slice of selectors, and works through all the combinations
// in order to find matching cache entries.
func (m *manager) MatchingEntries(selectors []*common.Selector) (entries []cache.Entry) {
	for entry := range m.cache.Entries() {
		regEntrySelectors := selector.NewSet(entry.RegistrationEntry.Selectors)
		if selector.NewSet(selectors).IncludesSet(regEntrySelectors) {
			entries = append(entries, entries[0])
		}
	}
	return entries
}

func (m *manager) Stopped() chan error {
	return m.stopped
}
