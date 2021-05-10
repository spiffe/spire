package catalog_test

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/stretchr/testify/assert"
)

func TestConstraints(t *testing.T) {
	t.Run("exactly one", func(t *testing.T) {
		testConstraint(t, catalog.ExactlyOne(),
			"expected exactly 1 but got 0",
			"expected exactly 1 but got 2",
		)
	})

	t.Run("maybe one", func(t *testing.T) {
		testConstraint(t, catalog.MaybeOne(),
			"",
			"expected at most 1 but got 2",
		)
	})

	t.Run("at least one", func(t *testing.T) {
		testConstraint(t, catalog.AtLeastOne(),
			"expected at least 1 but got 0",
			"",
		)
	})

	t.Run("zero or more", func(t *testing.T) {
		testConstraint(t, catalog.ZeroOrMore(),
			"",
			"",
		)
	})
}

func testConstraint(t *testing.T, constraints catalog.Constraints, zeroError, twoError string) {
	testCheck(t, constraints, 0, zeroError)
	testCheck(t, constraints, 1, "")
	testCheck(t, constraints, 2, twoError)
}

func testCheck(t *testing.T, constraints catalog.Constraints, count int, expectedErr string) {
	err := constraints.Check(count)
	if expectedErr == "" {
		assert.NoError(t, err)
	} else {
		assert.EqualError(t, err, expectedErr)
	}
}
