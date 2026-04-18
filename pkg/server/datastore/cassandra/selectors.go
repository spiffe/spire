package cassandra

import (
	"slices"
	"strings"

	datastorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/datastore/v1alpha1"
)

func selectorToString(s *datastorev1.Selector) string {
	return s.Type + "|" + s.Value
}

func selectorStringsToSelectorObjs(selectorStrings []string) []*datastorev1.Selector {
	selectors := make([]*datastorev1.Selector, len(selectorStrings))

	for i, s := range selectorStrings {
		sel := stringToSelector(s)
		if sel != nil {
			selectors[i] = sel
		}
	}

	slices.SortFunc(selectors, func(a, b *datastorev1.Selector) int {
		if typeCompare := strings.Compare(a.Type, b.Type); typeCompare != 0 {
			return typeCompare
		}

		return strings.Compare(a.Value, b.Value)
	})

	return selectors
}

func stringToSelector(s string) *datastorev1.Selector {
	parts := strings.SplitN(s, "|", 2)
	if len(parts) != 2 {
		return nil
	}
	return &datastorev1.Selector{
		Type:  parts[0],
		Value: parts[1],
	}
}
