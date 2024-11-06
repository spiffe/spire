package keyvaluestore

import "github.com/spiffe/spire/proto/spire/common"

type boolCmp struct{}

func (boolCmp) Cmp(a, b bool) int {
	switch {
	case a == b:
		return 0
	case !a:
		return -1
	default:
		return 1
	}
}

type selectorCmp struct{}

func (selectorCmp) Cmp(a, b *common.Selector) int {
	if a == nil {
		if b == nil {
			return 0
		}
		return -1
	}
	if b == nil {
		return 1
	}
	switch {
	case a.Type < b.Type:
		return -1
	case a.Type > b.Type:
		return 1
	case a.Value < b.Value:
		return -1
	case a.Value > b.Value:
		return 1
	default:
		return 0
	}
}
