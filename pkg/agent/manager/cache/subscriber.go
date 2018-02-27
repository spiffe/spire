package cache

import (
	"crypto/x509"
	"github.com/satori/go.uuid"
	"github.com/spiffe/spire/pkg/common/selector"
)

type WorkloadUpdate struct {
	cacheEntries []Entry
	bundle       []*x509.Certificate
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

//type sID string
// Get is a map keyed by the string representation of the selector sets, with a value mapped by Subscriber ID.
// used to maintain a subscription of workloads

type subscribers struct {
	selMap map[string][]uuid.UUID // map of selector to UID
	sidMap map[uuid.UUID]*Subscriber
}

func (s *subscribers) Add(sub *Subscriber) error {

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

func (s *subscribers) Remove(sid uuid.UUID) {
	s.sidMap[sid].done <- struct{}{}
	delete(s.sidMap, sid)
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

func dedupe(ids []uuid.UUID) (deduped []uuid.UUID) {
	uniqueMap := map[uuid.UUID]bool{}
	for i := range ids {
		uniqueMap[ids[i]] = true
	}
	for key, _ := range uniqueMap {
		deduped = append(deduped, key)
	}
	return
}
