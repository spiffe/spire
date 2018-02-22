package manager

import (
	"github.com/satori/go.uuid"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/selector"
)

type subscriber struct {
	c    chan cache.Entry
	sel  cache.Selectors
	done chan struct{}
}

//type sID string
// subscribers is a map keyed by the string representation of the selector sets, with a value mapped by Subscriber ID.
// used to maintain a subscription of workloads

type subscribers struct {
	selMap map[string][]uuid.UUID
	sidMap map[uuid.UUID]*subscriber
}

func (s *subscribers) Add(sub *subscriber) error {

	id, err := uuid.NewV4()
	if err != nil {
		return err
	}
	s.sidMap[id] = sub

	selSet := selector.NewSet(sub.sel)
	selPSet := selSet.Power()
	for sel := range selPSet {
		selStr := sel.String()
		s.selMap[selStr] = append(s.selMap[selStr], id)
	}

	return nil
}

func (s *subscribers) Notify(entry cache.Entry) {
	sids := []uuid.UUID{}
	selSet := selector.NewSet(entry.RegistrationEntry.Selectors)
	selPSet := selSet.Power()

	for sel := range selPSet {
		selStr := sel.String()
		sids = append(sids, s.selMap[selStr]...)
	}
	sids = dedupe(sids)
	for _, sid := range sids {
		s.sidMap[sid].c <- entry
	}
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
