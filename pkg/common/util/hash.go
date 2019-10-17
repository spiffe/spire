package util

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"

	"github.com/spiffe/spire/proto/spire/common"
)

func DeriveRegEntryhash(entry *common.RegistrationEntry) (key string) {
	var concatSelectors string
	SortSelectors(entry.Selectors)

	for _, selector := range entry.Selectors {
		concatSelectors = concatSelectors + "::" + selector.Type + ":" + selector.Value
	}

	hashValue := hash.Hash.Sum(sha256.New(), []byte(concatSelectors+entry.SpiffeId+entry.ParentId))

	return hex.EncodeToString(hashValue)
}
