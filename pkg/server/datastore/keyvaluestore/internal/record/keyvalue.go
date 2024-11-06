package record

func recordKey[O Object](r *Record[O]) string {
	if r == nil {
		return ""
	}
	return r.Object.Key()
}

type keyValue[V any] struct {
	Value V
	Key   string
}

type byKey[V any, C Cmp[V]] struct{}

func (byKey[V, C]) Cmp(a, b keyValue[V]) int {
	switch {
	case a.Key < b.Key:
		return -1
	case b.Key < a.Key:
		return 1
	default:
		return (C{}).Cmp(a.Value, b.Value)
	}
}

type byValue[V any, C Cmp[V]] struct{}

func (byValue[V, C]) Cmp(a, b keyValue[V]) int {
	cmp := (C{}).Cmp(a.Value, b.Value)
	if cmp != 0 {
		return cmp
	}
	switch {
	case a.Key < b.Key:
		return -1
	case b.Key < a.Key:
		return 1
	default:
		return 0
	}
}
