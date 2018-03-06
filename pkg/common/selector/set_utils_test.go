package selector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	selector1 = &Selector{Type: "foo", Value: "bar"}
	selector2 = &Selector{Type: "bar", Value: "bat"}
	selector3 = &Selector{Type: "bat", Value: "baz"}
	selector4 = &Selector{Type: "baz", Value: "quz"}
	selector5 = &Selector{Type: "quz", Value: "foo"}
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

func TestPowerSet(t *testing.T) {
	a := assert.New(t)

	selectorSet := NewSet(
		selector1,
		selector2,
		selector3,
		selector4,
		selector5,
	)

	expectedResults := []Set{
		NewSet(selector1),
		NewSet(selector2),
		NewSet(selector1, selector2),
		NewSet(selector3),
		NewSet(selector1, selector3),
		NewSet(selector2, selector3),
		NewSet(selector1, selector2, selector3),
		NewSet(selector4),
		NewSet(selector1, selector4),
		NewSet(selector2, selector4),
		NewSet(selector1, selector2, selector4),
		NewSet(selector3, selector4),
		NewSet(selector1, selector3, selector4),
		NewSet(selector2, selector3, selector4),
		NewSet(selector1, selector2, selector3, selector4),
		NewSet(selector5),
		NewSet(selector1, selector5),
		NewSet(selector2, selector5),
		NewSet(selector1, selector2, selector5),
		NewSet(selector3, selector5),
		NewSet(selector1, selector3, selector5),
		NewSet(selector2, selector3, selector5),
		NewSet(selector1, selector2, selector3, selector5),
		NewSet(selector4, selector5),
		NewSet(selector1, selector4, selector5),
		NewSet(selector2, selector4, selector5),
		NewSet(selector1, selector2, selector4, selector5),
		NewSet(selector3, selector4, selector5),
		NewSet(selector1, selector3, selector4, selector5),
		NewSet(selector2, selector3, selector4, selector5),
		NewSet(selector1, selector2, selector3, selector4, selector5),
	}

	var results []Set
	for result := range PowerSet(selectorSet.(*set)) {
		results = append(results, result)
	}

	if a.Equal(len(expectedResults), len(results)) {
		for i := 0; i < len(expectedResults); i++ {
			a.True(EqualSet(expectedResults[i].(*set), results[i].(*set)))
		}
	}
}
