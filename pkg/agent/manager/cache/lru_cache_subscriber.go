package cache

import (
	"sync"

	"github.com/spiffe/spire/proto/spire/common"
)

// baseSubscriber is the non-generic interface stored in selector indices.
type baseSubscriber interface {
	getSet() selectorSet
	superSetOf(selectorSet) bool

	// requiresSVIDs reports whether the subscriber needs SVIDs for the
	// entries matching its selectors. Only such subscribers count as active
	// subscribers of a record, which drives SVID minting and retention.
	requiresSVIDs() bool

	// publish builds an update from the current state of the cache and
	// delivers it to the subscriber. Callers must hold the cache lock.
	publish()
}

// Subscriber is the public interface for cache subscribers.
type Subscriber[U any] interface {
	Updates() <-chan *U
	Finish()
}

type lruCacheSubscriber[U any] struct {
	cache   subscriberCache
	set     selectorSet
	setFree func()

	// buildUpdate builds the update for the subscriber selector set.
	buildUpdate func(selectorSet) *U
	svids       bool

	mu   sync.Mutex
	c    chan *U
	done bool
}

// subscriberCache is the interface the subscriber uses to call back into the cache.
type subscriberCache interface {
	unsubscribe(sub baseSubscriber)
}

func newLRUCacheSubscriber[U any](cache subscriberCache, selectors []*common.Selector, buildUpdate func(selectorSet) *U, requiresSVIDs bool) *lruCacheSubscriber[U] {
	set, setFree := allocSelectorSet(selectors...)
	return &lruCacheSubscriber[U]{
		cache:       cache,
		set:         set,
		setFree:     setFree,
		buildUpdate: buildUpdate,
		svids:       requiresSVIDs,
		c:           make(chan *U, 1),
	}
}

func (s *lruCacheSubscriber[U]) Updates() <-chan *U {
	return s.c
}

func (s *lruCacheSubscriber[U]) Finish() {
	s.mu.Lock()
	done := s.done
	if !done {
		s.done = true
		close(s.c)
	}
	s.mu.Unlock()
	if !done {
		s.cache.unsubscribe(s)
		s.setFree()
		s.set = nil
	}
}

func (s *lruCacheSubscriber[U]) notify(update *U) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return
	}

	select {
	case <-s.c:
	default:
	}
	s.c <- update
}

// baseSubscriber interface implementation
func (s *lruCacheSubscriber[U]) getSet() selectorSet {
	return s.set
}

func (s *lruCacheSubscriber[U]) superSetOf(other selectorSet) bool {
	return s.set.SuperSetOf(other)
}

func (s *lruCacheSubscriber[U]) requiresSVIDs() bool {
	return s.svids
}

func (s *lruCacheSubscriber[U]) publish() {
	s.notify(s.buildUpdate(s.set))
}
