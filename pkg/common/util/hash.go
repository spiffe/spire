package util

import (
	"crypto/sha256"
	"github.com/spiffe/spire/proto/common"
	"hash"
	"sort"
)

func DeriveRegEntryhash(entry *common.RegistrationEntry) (key string) {
	var concatSelectors string
	sort.Slice(entry.Selectors, SelectorsSortFunction(entry.Selectors))

	for _, selector := range entry.Selectors {
		concatSelectors = concatSelectors + "::" + selector.Type + ":" + selector.Value
	}

	hashValue := hash.Hash.Sum(sha256.New(), []byte(concatSelectors+entry.SpiffeId+entry.ParentId))

	return string(hashValue)
}
