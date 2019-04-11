package cache

import (
	"sync"

	"github.com/spiffe/spire/proto/spire/common"
)

type Subscriber interface {
	Updates() <-chan *WorkloadUpdate
	Finish()
}

type subscriber struct {
	cache *Cache
	set   selectorSet

	mu   sync.Mutex
	c    chan *WorkloadUpdate
	done bool
}

func newSubscriber(cache *Cache, selectors []*common.Selector) *subscriber {
	return &subscriber{
		cache: cache,
		set:   allocSelectorSet(selectors...),
		c:     make(chan *WorkloadUpdate, 1),
	}
}

func (s *subscriber) Updates() <-chan *WorkloadUpdate {
	return s.c
}

func (s *subscriber) Finish() {
	s.mu.Lock()
	done := s.done
	if !done {
		s.done = true
		close(s.c)
	}
	s.mu.Unlock()
	if !done {
		s.cache.unsubscribe(s)
	}
}

func (s *subscriber) notify(update *WorkloadUpdate) {
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
