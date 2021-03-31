package util_test

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/assert"
)

func TestEqualsSelectors(t *testing.T) {
	assert := assert.New(t)

	s1 := []*common.Selector{
		{Type: "a", Value: "1"},
		{Type: "b", Value: "2"},
	}

	// Equals with different order
	s2 := []*common.Selector{
		{Type: "b", Value: "2"},
		{Type: "a", Value: "1"},
	}
	assert.True(util.EqualsSelectors(s1, s2))

	// Different type
	s2 = []*common.Selector{
		{Type: "c", Value: "2"},
		{Type: "a", Value: "1"},
	}
	assert.False(util.EqualsSelectors(s1, s2))

	// Different value
	s2 = []*common.Selector{
		{Type: "a", Value: "1"},
		{Type: "b", Value: "3"},
	}
	assert.False(util.EqualsSelectors(s1, s2))

	// More elements
	s2 = []*common.Selector{
		{Type: "a", Value: "1"},
		{Type: "b", Value: "2"},
		{Type: "c", Value: "3"},
	}
	assert.False(util.EqualsSelectors(s1, s2))
}
