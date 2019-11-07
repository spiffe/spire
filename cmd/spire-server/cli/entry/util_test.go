package entry

import (
	"testing"

	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	a.True(hasSelectors(entry, selectorToFlag(t, selectors[0:1])))
	a.True(hasSelectors(entry, selectorToFlag(t, selectors[2:3])))
	a.True(hasSelectors(entry, selectorToFlag(t, selectors[1:3])))

	newSelectors := []*common.Selector{
		{Type: "bar", Value: "foo"},
		{Type: "bat", Value: "bar"},
	}
	selectors = append(selectors, newSelectors...)

	a.False(hasSelectors(entry, selectorToFlag(t, selectors[3:4])))
	a.False(hasSelectors(entry, selectorToFlag(t, selectors[2:4])))
}

func selectorToFlag(t *testing.T, selectors []*common.Selector) StringsFlag {
	resp := StringsFlag{}
	for _, s := range selectors {
		str := s.Type + ":" + s.Value
		require.NoError(t, resp.Set(str))
	}

	return resp
}
