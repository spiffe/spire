package authorizedentries

import "sync"

var (
	stringSetPool = sync.Pool{
		New: func() any {
			return make(stringSet)
		},
	}
)

type stringSet map[string]struct{}

func allocStringSet() stringSet {
	return stringSetPool.Get().(stringSet)
}

func freeStringSet(set stringSet) {
	clearStringSet(set)
	stringSetPool.Put(set)
}

func clearStringSet(set stringSet) {
	for k := range set {
		delete(set, k)
	}
}
