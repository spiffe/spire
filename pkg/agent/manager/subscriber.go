package manager

import (
	"crypto/x509"
	"github.com/satori/go.uuid"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/selector"
)

type workloadUpdate struct {
	cacheEntries []cache.Entry
	bundle       []*x509.Certificate
}

type subscriber struct {
	c    chan *workloadUpdate
	sel  cache.Selectors
	done chan struct{}
}

//type sID string
// Get is a map keyed by the string representation of the selector sets, with a value mapped by Subscriber ID.
// used to maintain a subscription of workloads

type subscribers struct {
	selMap map[string][]uuid.UUID // map of selector to UID
	sidMap map[uuid.UUID]*subscriber
}

func (s *subscribers) Add(sub *subscriber) error {

	id, err := uuid.NewV4()
	if err != nil {
		return err
	}
	s.sidMap[id] = sub

	selSet := selector.NewSetFromRaw(sub.sel)
	selPSet := selSet.Power()
	for sel := range selPSet {
		selStr := sel.String()
		s.selMap[selStr] = append(s.selMap[selStr], id)
	}

	return nil
}

func (s *subscribers) Get(sels cache.Selectors) []uuid.UUID {
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
