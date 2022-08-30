package catalog

import (
	"fmt"
)

func ExactlyOne() Constraints {
	return Constraints{Min: 1, Max: 1}
}

func MaybeOne() Constraints {
	return Constraints{Min: 0, Max: 1}
}

func AtLeastOne() Constraints {
	return Constraints{Min: 1, Max: 0}
}

func ZeroOrMore() Constraints {
	return Constraints{Min: 0, Max: 0}
}

type Constraints struct {
	// Min is the minimum number of plugins required of a specific type. If
	// zero, there is no lower bound (i.e. the plugin type is optional).
	Min int

	// Max is the maximum number of plugins required of a specific type. If
	// zero, there is no upper bound.
	Max int
}

func (c Constraints) Check(count int) error {
	switch {
	case c.Max > 0 && c.Min == c.Max && c.Min != count:
		return fmt.Errorf("expected exactly %d but got %d", c.Min, count)
	case c.Min > 0 && c.Min > count:
		return fmt.Errorf("expected at least %d but got %d", c.Min, count)
	case c.Max > 0 && c.Max < count:
		return fmt.Errorf("expected at most %d but got %d", c.Max, count)
	}
	return nil
}
