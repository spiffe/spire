package authorizedentries

import (
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

type selectorSet map[Selector]struct{}

func selectorSetFromProto(selectors []*types.Selector) selectorSet {
	set := make(selectorSet, len(selectors))
	for _, selector := range selectors {
		set[Selector{Type: selector.Type, Value: selector.Value}] = struct{}{}
	}
	return set
}

// Returns true if sub is a subset of whole
func isSubset(sub, whole selectorSet) bool {
	if len(sub) > len(whole) {
		return false
	}
	for s := range sub {
		if _, ok := whole[s]; !ok {
			return false
		}
	}
	return true
}
