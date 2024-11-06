package record

import "golang.org/x/exp/constraints"

type Cmp[T any] interface {
	~struct{}
	Cmp(T, T) int
}

type OrderedCmp[T constraints.Ordered] struct{}

func (OrderedCmp[T]) Cmp(a, b T) int {
	switch {
	case a == b:
		return 0
	case a < b:
		return -1
	default:
		return 1
	}
}
