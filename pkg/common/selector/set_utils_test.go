package selector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	selector1 *Selector = &Selector{Type: "foo", Value: "bar"}
	selector2 *Selector = &Selector{Type: "bar", Value: "bat"}
	selector3 *Selector = &Selector{Type: "bat", Value: "baz"}
	selector4 *Selector = &Selector{Type: "baz", Value: "quz"}
	selector5 *Selector = &Selector{Type: "quz", Value: "foo"}
)

func TestEqualSet(t *testing.T) {
	a := assert.New(t)

	set1 := Set{selector1, selector2}
	set2 := Set{selector1, selector2}
	a.Equal(set1, set2)
	a.NotEqual(set1, set2[1:])
}

func TestPowerSet(t *testing.T) {
	a := assert.New(t)

	selectorSet := Set{
		selector1,
		selector2,
		selector3,
		selector4,
		selector5,
	}

	expectedResults := []Set{
		{selector1},
		{selector2},
		{selector1, selector2},
		{selector3},
		{selector1, selector3},
		{selector2, selector3},
		{selector1, selector2, selector3},
		{selector4},
		{selector1, selector4},
		{selector2, selector4},
		{selector1, selector2, selector4},
		{selector3, selector4},
		{selector1, selector3, selector4},
		{selector2, selector3, selector4},
		{selector1, selector2, selector3, selector4},
		{selector5},
		{selector1, selector5},
		{selector2, selector5},
		{selector1, selector2, selector5},
		{selector3, selector5},
		{selector1, selector3, selector5},
		{selector2, selector3, selector5},
		{selector1, selector2, selector3, selector5},
		{selector4, selector5},
		{selector1, selector4, selector5},
		{selector2, selector4, selector5},
		{selector1, selector2, selector4, selector5},
		{selector3, selector4, selector5},
		{selector1, selector3, selector4, selector5},
		{selector2, selector3, selector4, selector5},
		{selector1, selector2, selector3, selector4, selector5},
	}

	var results []Set
	for result := range PowerSet(selectorSet) {
		results = append(results, result)
	}

	if a.Equal(len(expectedResults), len(results)) {
		for i := 0; i < len(expectedResults); i++ {
			a.True(EqualSet(expectedResults[i], results[i]))
		}
	}
}
