package selector

import (
	"math"
	"strconv"
	"strings"
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

// EqualSet determines whether two slices of selectors are equal or not
func EqualSet(a, b Set) bool {
	if a == nil || b == nil {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
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

// powerSet, given a set of selectors, returns every possible combination
// of selector subsets.
//
// https://en.wikipedia.org/wiki/Power_set
func powerSet(s Set, c chan Set) {
	powSetSize := math.Pow(2, float64(len(s)))

	// Skip the empty set by starting the counter at 1
	for i := 1; i < int(powSetSize); i++ {
		set := Set{}

		// Form binary representation of the counter
		binaryString := strconv.FormatUint(uint64(i), 2)
		binary := strings.Split(binaryString, "")

		// Walk through the binary, and append
		// "enabled" elements to the working set
		for position := 0; position < len(binary); position++ {
			// Read the binary right to left
			negPosition := (len(binary) - position - 1)
			if binary[negPosition] == "1" {
				set = append(set, s[position])
			}
		}

		c <- set
	}
}
