package cache

import (
	"sync"

	"github.com/spiffe/spire/proto/spire/common"
)

type lruCacheSubscriber struct {
	cache   *LRUCache
	set     selectorSet
	setFree func()

	mu   sync.Mutex
	c    chan *WorkloadUpdate
	done bool
}

func newLRUCacheSubscriber(cache *LRUCache, selectors []*common.Selector) *lruCacheSubscriber {
	set, setFree := allocSelectorSet(selectors...)
	return &lruCacheSubscriber{
		cache:   cache,
		set:     set,
		setFree: setFree,
		c:       make(chan *WorkloadUpdate, 1),
	}
}

func (s *lruCacheSubscriber) Updates() <-chan *WorkloadUpdate {
	return s.c
}

func (s *lruCacheSubscriber) Finish() {
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

func (s *lruCacheSubscriber) notify(update *WorkloadUpdate) {
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
