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
func PowerSet(selectors *set) <-chan Set {
	c := make(chan Set)

	go func() {
		powerSet(selectors, c)

		close(c)
	}()

	return c
}

// EqualSet determines whether two sets of selectors are equal or not
func EqualSet(a, b *set) bool {
	if a.Size() != b.Size() {
		return false
	}
	return IncludesSet(a, b)
}

// Includes determines whether a given selector is present in a set
func Includes(set *set, item *Selector) bool {
	return (*set)[*item] == item
}

// IncludesSet returns true if s2 is included in s1. This is, all the s2 selectors
// are also present in s1.
func IncludesSet(s1, s2 *set) bool {
	// If s2 has more elements than s1, it cannot be included.
	if len(*s2) > len(*s1) {
		return false
	}

	for key2, sel2 := range *s2 {
		if sel1, found := (*s1)[key2]; found {
			if *sel2 != *sel1 {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

// powerSet, given a set of selectors, returns every possible combination
// of selector subsets.
//
// https://en.wikipedia.org/wiki/Power_set
func powerSet(s *set, c chan Set) {
	sarr := s.Array()
	powSetSize := math.Pow(2, float64(len(*s)))

	// Skip the empty set by starting the counter at 1
	for i := 1; i < int(powSetSize); i++ {
		set := &set{}

		// Form binary representation of the counter
		binaryString := strconv.FormatUint(uint64(i), 2)
		binary := strings.Split(binaryString, "")

		// Walk through the binary, and append
		// "enabled" elements to the working set
		for position := 0; position < len(binary); position++ {
			// Read the binary right to left
			negPosition := (len(binary) - position - 1)
			if binary[negPosition] == "1" {
				set.Add(sarr[position])
			}
		}

		c <- set
	}
}
