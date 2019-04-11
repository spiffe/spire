package cache

import (
	"sync"

	"github.com/spiffe/spire/proto/spire/common"
)

var (
	stringSetPool = sync.Pool{
		New: func() interface{} {
			return make(stringSet)
		},
	}

	subscriberSetPool = sync.Pool{
		New: func() interface{} {
			return make(subscriberSet)
		},
	}

	selectorSetPool = sync.Pool{
		New: func() interface{} {
			return make(selectorSet)
		},
	}

	entriesSetPool = sync.Pool{
		New: func() interface{} {
			return make(entriesSet)
		},
	}
)

// unique set of strings, allocated from a pool
type stringSet map[string]struct{}

func allocStringSet(ss ...string) stringSet {
	set := stringSetPool.Get().(stringSet)
	set.Merge(ss...)
	return set
}

func freeStringSet(set stringSet) {
	for k := range set {
		delete(set, k)
	}
	stringSetPool.Put(set)
}

func (set stringSet) Merge(ss ...string) {
	for _, s := range ss {
		set[s] = struct{}{}
	}
}

// unique set of subscribers, allocated from a pool
type subscriberSet map[*subscriber]struct{}

func allocSubscriberSet() subscriberSet {
	return subscriberSetPool.Get().(subscriberSet)
}

func freeSubscriberSet(set subscriberSet) {
	for k := range set {
		delete(set, k)
	}
	subscriberSetPool.Put(set)
}

// unique set of selectors, allocated from a pool
type selector struct {
	Type  string
	Value string
}

func makeSelector(s *common.Selector) selector {
	return selector{
		Type:  s.Type,
		Value: s.Value,
	}
}

type selectorSet map[selector]struct{}

func allocSelectorSet(ss ...*common.Selector) selectorSet {
	set := selectorSetPool.Get().(selectorSet)
	set.Merge(ss...)
	return set
}

func freeSelectorSet(set selectorSet) {
	for k := range set {
		delete(set, k)
	}
	selectorSetPool.Put(set)
}

func (set selectorSet) Merge(ss ...*common.Selector) {
	for _, s := range ss {
		set[selector{Type: s.Type, Value: s.Value}] = struct{}{}
	}
}

func (set selectorSet) MergeSet(other selectorSet) {
	for s := range other {
		set[s] = struct{}{}
	}
}

func (set selectorSet) In(ss ...*common.Selector) bool {
	for _, s := range ss {
		if _, ok := set[makeSelector(s)]; !ok {
			return false
		}
	}
	return true
}

// unique set of cache entries, allocated from a pool
type entriesSet map[*cacheEntry]struct{}

func allocEntriesSet() entriesSet {
	return entriesSetPool.Get().(entriesSet)
}

func freeEntriesSet(set entriesSet) {
	for k := range set {
		delete(set, k)
	}
	entriesSetPool.Put(set)
}
