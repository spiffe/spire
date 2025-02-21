package selector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	selector1 = &Selector{Type: "foo", Value: "bar"}
	selector2 = &Selector{Type: "bar", Value: "bat"}
)

func TestEqualSet(t *testing.T) {
	a := assert.New(t)

	set1 := NewSet(selector1, selector2)
	set2 := NewSet(selector1, selector2)
	a.True(set1.Equal(set2))
	a.True(set2.Equal(set1))
	set2.Remove(selector1)
	a.True(!set1.Equal(set2))
}
