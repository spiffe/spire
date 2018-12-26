package cache

import (
	"sync"

	"github.com/gofrs/uuid"
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

type subscriber struct {
	c      chan *WorkloadUpdate
	m      sync.Mutex
	sel    Selectors
	sid    uuid.UUID
	active bool
}

type subscribers struct {
	selMap map[string][]uuid.UUID // map of selector to UID
	sidMap map[uuid.UUID]*subscriber
	m      sync.Mutex
}

func NewSubscriber(selectors Selectors) (*subscriber, error) {
	u, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	return &subscriber{
		c:      make(chan *WorkloadUpdate, 1),
		sel:    selectors,
		sid:    u,
		active: true,
	}, nil
}

// Updates returns the channel where the updates are received.
func (sub *subscriber) Updates() <-chan *WorkloadUpdate {
	return sub.c
}

// Finish finishes subscriber's updates subscription. Hence no more updates
// will be received on Updates() channel.
func (sub *subscriber) Finish() {
	sub.m.Lock()
	defer sub.m.Unlock()
	sub.active = false
	close(sub.c)
}

func (s *subscribers) add(sub *subscriber) error {
	s.m.Lock()
	defer s.m.Unlock()
	s.sidMap[sub.sid] = sub

	selSet := selector.NewSetFromRaw(sub.sel)
	selPSet := selSet.Power()
	for sel := range selPSet {
		selStr := sel.String()
		s.selMap[selStr] = append(s.selMap[selStr], sub.sid)
	}

	return nil
}

func (s *subscribers) get(sels Selectors) (subs []*subscriber) {
	s.m.Lock()
	defer s.m.Unlock()
	sids := s.getSubIds(sels)
	for _, id := range sids {
		subs = append(subs, s.sidMap[id])
	}
	return
}

func (s *subscribers) getAll() (subs []*subscriber) {
	s.m.Lock()
	defer s.m.Unlock()

	for _, sub := range s.sidMap {
		subs = append(subs, sub)
	}
	return
}

func (s *subscribers) remove(sub *subscriber) {
	s.m.Lock()
	defer s.m.Unlock()
	delete(s.sidMap, sub.sid)
	for sel, sids := range s.selMap {
		for i, uid := range sids {
			if uid == sub.sid {
				s.selMap[sel] = append(sids[:i], sids[i+1:]...)
			}
		}
	}
}

func (s *subscribers) getSubIds(sels Selectors) []uuid.UUID {
	subIds := []uuid.UUID{}

	selSet := selector.NewSetFromRaw(sels)
	selPSet := selSet.Power()

	for sel := range selPSet {
		selStr := sel.String()
		subIds = append(subIds, s.selMap[selStr]...)
	}

	subIds = dedupe(subIds)

	return subIds
}

func NewSubscribers() *subscribers {
	return &subscribers{
		selMap: make(map[string][]uuid.UUID),
		sidMap: make(map[uuid.UUID]*subscriber),
	}
}

func dedupe(ids []uuid.UUID) (deduped []uuid.UUID) {
	uniqueMap := map[uuid.UUID]bool{}
	for i := range ids {
		uniqueMap[ids[i]] = true
	}
	for key := range uniqueMap {
		deduped = append(deduped, key)
	}
	return
}
