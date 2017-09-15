package util

import "github.com/spiffe/spire/pkg/common"

func SelectorsSortFunction(selectors []*common.Selector) (func(i,j int) bool) {

	return func(i, j int) bool {
		if selectors[i].Type != selectors[j].Type {
			return selectors[i].Type < selectors[j].Type
		} else {
			return selectors[i].Value < selectors[j].Value
		}
	}
}