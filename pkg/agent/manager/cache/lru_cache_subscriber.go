package cache

import (
	"sync"

	"github.com/spiffe/spire/proto/spire/common"
)

// baseSubscriber is the non-generic interface stored in selector indices.
type baseSubscriber interface {
	getSet() selectorSet
	superSetOf(selectorSet) bool
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

	mu   sync.Mutex
	c    chan *U
	done bool
}

// subscriberCache is the interface the subscriber uses to call back into the cache.
type subscriberCache interface {
	unsubscribe(sub baseSubscriber)
}

func newLRUCacheSubscriber[U any](cache subscriberCache, selectors []*common.Selector) *lruCacheSubscriber[U] {
	set, setFree := allocSelectorSet(selectors...)
	return &lruCacheSubscriber[U]{
		cache:   cache,
		set:     set,
		setFree: setFree,
		c:       make(chan *U, 1),
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
