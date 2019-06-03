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

	recordSetPool = sync.Pool{
		New: func() interface{} {
			return make(recordSet)
		},
	}
)

// unique set of strings, allocated from a pool
type stringSet map[string]struct{}

func allocStringSet(ss ...string) (stringSet, func()) {
	set := stringSetPool.Get().(stringSet)
	set.Merge(ss...)
	return set, func() {
		clearStringSet(set)
		stringSetPool.Put(set)
	}
}

func clearStringSet(set stringSet) {
	for k := range set {
		delete(set, k)
	}
}

func (set stringSet) Merge(ss ...string) {
	for _, s := range ss {
		set[s] = struct{}{}
	}
}

// unique set of subscribers, allocated from a pool
type subscriberSet map[*subscriber]struct{}

func allocSubscriberSet() (subscriberSet, func()) {
	set := subscriberSetPool.Get().(subscriberSet)
	return set, func() {
		clearSubscriberSet(set)
		subscriberSetPool.Put(set)
	}
}

func clearSubscriberSet(set subscriberSet) {
	for k := range set {
		delete(set, k)
	}
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

func allocSelectorSet(ss ...*common.Selector) (selectorSet, func()) {
	set := selectorSetPool.Get().(selectorSet)
	set.Merge(ss...)
	return set, func() {
		clearSelectorSet(set)
		selectorSetPool.Put(set)
	}
}

func clearSelectorSet(set selectorSet) {
	for k := range set {
		delete(set, k)
	}
}

func (set selectorSet) Merge(ss ...*common.Selector) {
	for _, s := range ss {
		set[makeSelector(s)] = struct{}{}
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

// unique set of cache records, allocated from a pool
type recordSet map[*cacheRecord]struct{}

func allocRecordSet() (recordSet, func()) {
	set := recordSetPool.Get().(recordSet)
	return set, func() {
		clearRecordSet(set)
		recordSetPool.Put(set)
	}
}

func clearRecordSet(set recordSet) {
	for k := range set {
		delete(set, k)
	}
}
