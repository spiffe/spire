package selector

import (
	"crypto/sha256"
	"hash"
)

// PowerSet implements a range-able combination generator. It takes a set, and
// returns a channel over which all possible combinations of selectors are eventually
// returned. It is meant to aid in the discovery of applicable cache entries, given the
// superset of selectors discovered during attestation.
func PowerSet(selectors Set) <-chan Set {
	c := make(chan Set)

	go func() {
		powerSet(selectors, c)

		close(c)
	}()

	return c
}

// EqualSet determines whether two sets of selectors are equal or not
func EqualSet(a, b Set) bool {
	if len(a) != len(b) {
		return false
	}

	for keyA, selA := range a {
		if selA != b[keyA] {
			return false
		}
	}

	return true
}

// Includes determines whether a given selector is present in a set
func Includes(set Set, item *Selector) bool {
	for _, s := range set {
		if item == s {
			return true
		}
	}

	return false
}

// IncludesSet returns true if s2 is included in s1. This is, all the s2 selectors
// are also present in s1.
func IncludesSet(s1, s2 Set) bool {
	// If s2 has more elements than s1, it cannot be included.
	if len(s2) > len(s1) {
		return false
	}

	for key2, sel2 := range s2 {
		if sel2 != s1[key2] {
			return false
		}
	}
	return true
}

// powerSet, given a set of selectors, returns every possible combination
// of selector subsets.
//
// https://en.wikipedia.org/wiki/Power_set
func powerSet(s Set, c chan Set) {
	set := Set{}
	for k, sel := range s {
		set[k] = sel
		// Copy the last set to have as starting point for the next subset
		lastset := Set{}
		for lk, lsel := range set {
			lastset[lk] = lsel
		}
		c <- set
		set = lastset
	}
}

func deriveKey(selector *Selector) string {
	selectorString := selector.Type + ":" + selector.Value
	hashedSelectors := hash.Hash.Sum(sha256.New(), []byte(selectorString))
	return string(hashedSelectors)
}
