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
	i := sort.Search(len(ss), func(i int) bool {
		switch {
		case ss[i].Type < s.Type:
			return false
		case ss[i].Type > s.Type:
			return true
		default:
			return ss[i].Value >= s.Value
		}
	})
	if i < len(ss) && ss[i].Type == s.Type && ss[i].Value == s.Value {
		// already inserted
		return ss
	}
	// otherwise, shift and insert
	ss = append(ss, nil)
	copy(ss[i+1:], ss[i:])
	ss[i] = s
	return ss
}
