package cache

import (
	"sync"

	"github.com/spiffe/spire/pkg/common/selector"
)

type Subscriber interface {
	Updates() <-chan *WorkloadUpdate
	Finish()
}

type WorkloadUpdate struct {
	Entries          []*Entry
	Bundle           *Bundle
	FederatedBundles map[string]*Bundle
}

type subscribers struct {
	m     sync.Mutex
	bySel map[string]map[*subscriber]struct{}
	byPtr map[*subscriber]struct{}
}

func newSubscribers() *subscribers {
	return &subscribers{
		bySel: make(map[string]map[*subscriber]struct{}),
		byPtr: make(map[*subscriber]struct{}),
	}
}

func (s *subscribers) add(sel Selectors) *subscriber {
	sub := newSubscriber(s, sel)

	s.m.Lock()
	defer s.m.Unlock()

	s.byPtr[sub] = struct{}{}

	for sel := range sub.selSet.Power() {
		selKey := sel.String()
		subs, ok := s.bySel[selKey]
		if !ok {
			subs = make(map[*subscriber]struct{})
			s.bySel[selKey] = subs
		}
		subs[sub] = struct{}{}
	}

	return sub
}

func (s *subscribers) get(sels Selectors) []*subscriber {
	s.m.Lock()
	defer s.m.Unlock()

	selSet := selector.NewSetFromRaw(sels)

	var subs []*subscriber
	for sel := range selSet.Power() {
		for sub := range s.bySel[sel.String()] {
			subs = append(subs, sub)
		}
	}

	return dedupe(subs)
}

func (s *subscribers) getAll() []*subscriber {
	s.m.Lock()
	defer s.m.Unlock()

	subs := make([]*subscriber, 0, len(s.byPtr))
	for sub := range s.byPtr {
		subs = append(subs, sub)
	}

	return subs
}

func (s *subscribers) remove(sub *subscriber) {
	s.m.Lock()
	defer s.m.Unlock()

	delete(s.byPtr, sub)
	for k, subs := range s.bySel {
		delete(subs, sub)
		if len(subs) == 0 {
			delete(s.bySel, k)
		}
	}
}

type subscriber struct {
	selSet selector.Set
	parent *subscribers

	m          sync.Mutex
	closed     bool
	updateChan chan *WorkloadUpdate
}

func newSubscriber(parent *subscribers, sel Selectors) *subscriber {
	return &subscriber{
		selSet:     selector.NewSetFromRaw(sel),
		parent:     parent,
		updateChan: make(chan *WorkloadUpdate, 1),
	}
}

func (sub *subscriber) sendUpdate(upd *WorkloadUpdate) {
	sub.m.Lock()
	defer sub.m.Unlock()
	if sub.closed {
		return
	}
	// drain any existing event
	select {
	case <-sub.updateChan:
	default:
	}
	sub.updateChan <- upd
}

// Updates returns the channel where the updates are received.
func (sub *subscriber) Updates() <-chan *WorkloadUpdate {
	return sub.updateChan
}

// Finish finishes subscriber's updates subscription. Hence no more updates
// will be received on Updates() channel.
func (sub *subscriber) Finish() {
	sub.m.Lock()
	if !sub.closed {
		sub.closed = true
		close(sub.updateChan)
	}
	sub.m.Unlock()

	sub.parent.remove(sub)
}

func dedupe(subs []*subscriber) (deduped []*subscriber) {
	set := map[*subscriber]struct{}{}
	for _, sub := range subs {
		set[sub] = struct{}{}
	}
	for sub := range set {
		deduped = append(deduped, sub)
	}
	return deduped
}
