package entry

import (
	"testing"

	"github.com/spiffe/spire/proto/common"
	"github.com/stretchr/testify/assert"
)

func TestHasSelectors(t *testing.T) {
	selectors := []*common.Selector{
		{Type: "foo", Value: "bar"},
		{Type: "bar", Value: "bat"},
		{Type: "bat", Value: "baz"},
	}

	entry := &common.RegistrationEntry{
		ParentId:  "spiffe://example.org/foo",
		SpiffeId:  "spiffe://example.org/bar",
		Selectors: selectors,
	}

	a := assert.New(t)
	a.True(hasSelectors(entry, selectorToFlag(selectors[0:1])))
	a.True(hasSelectors(entry, selectorToFlag(selectors[2:3])))
	a.True(hasSelectors(entry, selectorToFlag(selectors[1:3])))

	newSelectors := []*common.Selector{
		{Type: "bar", Value: "foo"},
		{Type: "bat", Value: "bar"},
	}
	selectors = append(selectors, newSelectors...)

	a.False(hasSelectors(entry, selectorToFlag(selectors[3:4])))
	a.False(hasSelectors(entry, selectorToFlag(selectors[2:4])))
}

func selectorToFlag(selectors []*common.Selector) StringsFlag {
	resp := StringsFlag{}
	for _, s := range selectors {
		str := s.Type + ":" + s.Value
		resp.Set(str)
	}

	return resp
}
