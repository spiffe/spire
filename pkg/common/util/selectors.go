package util

import "github.com/spiffe/spire/proto/spire/common"

func EqualsSelectors(a, b []*common.Selector) bool {
	selectorsA := a
	SortSelectors(selectorsA)

	selectorsB := b
	SortSelectors(selectorsB)

	return compareSelectors(selectorsA, selectorsB) == 0
}
