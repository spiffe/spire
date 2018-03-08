package cache

import (
	"crypto/x509"
	"sync"

	"github.com/satori/go.uuid"
	"github.com/spiffe/spire/pkg/common/selector"
)

type WorkloadUpdate struct {
	Entries []Entry
	Bundle  []*x509.Certificate
}

type Subscriber struct {
	C    chan *WorkloadUpdate
	sel  Selectors
	done chan struct{}
	sid  uuid.UUID
}

func NewSubscriber(selectors Selectors, done chan struct{}) (*Subscriber, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	return &Subscriber{
		C:    make(chan *WorkloadUpdate),
		sel:  selectors,
		done: done,
		sid:  id,
	}, nil
}

type subscribers struct {
	selMap map[string][]uuid.UUID // map of selector to UID
	sidMap map[uuid.UUID]*Subscriber
	m      sync.Mutex
}

func (s *subscribers) Add(sub *Subscriber) error {
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

func (s *subscribers) Get(sels Selectors) (subs []*Subscriber) {
	sids := s.getSubIds(sels)
	for _, id := range sids {
		subs = append(subs, s.sidMap[id])
	}
	return
}

func (s *subscribers) remove(sub *Subscriber) {
	s.m.Lock()
	defer s.m.Unlock()
	close(sub.C)
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
		sidMap: make(map[uuid.UUID]*Subscriber),
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
