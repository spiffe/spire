package selector

import (
	"sort"

	"github.com/spiffe/spire/proto/spire/common"
)

func Dedupe(selectorSets ...[]*common.Selector) []*common.Selector {
	var deduped []*common.Selector
	for _, selectorSet := range selectorSets {
		for _, selector := range selectorSet {
			deduped = insertSelector(deduped, selector)
		}
	}
	return deduped
}

func insertSelector(ss []*common.Selector, s *common.Selector) []*common.Selector {
	// find the insertion index
	i, found := sort.Find(len(ss), func(i int) int {
		switch {
		case s.Type < ss[i].Type:
			return -1
		case s.Type > ss[i].Type:
			return 1
		case s.Value < ss[i].Value:
			return -1
		case s.Value > ss[i].Value:
			return 1
		default:
			return 0
		}
	})
	if found {
		// already inserted
		return ss
	}
	// otherwise, shift and insert
	ss = append(ss, nil)
	copy(ss[i+1:], ss[i:])
	ss[i] = s
	return ss
}
