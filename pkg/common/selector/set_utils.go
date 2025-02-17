package selector

// EqualSet determines whether two sets of selectors are equal or not
func EqualSet(a, b *set) bool {
	if a.Size() != b.Size() {
		return false
	}
	return IncludesSet(a, b)
}

// Includes determines whether a given selector is present in a set
func Includes(set *set, item *Selector) bool {
	in, ok := (*set)[*item]
	return ok && (*item) == (*in)
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
