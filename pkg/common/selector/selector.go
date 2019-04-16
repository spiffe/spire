// The selector package exports functions useful for manipulating and generating
// spire selectors
package selector

import (
	"github.com/spiffe/spire/proto/spire/common"
)

type Selector struct {
	Type  string
	Value string
}

func New(c *common.Selector) *Selector {
	s := &Selector{
		Type:  c.Type,
		Value: c.Value,
	}
	return s
}

func (s *Selector) Raw() *common.Selector {
	c := &common.Selector{
		Type:  s.Type,
		Value: s.Value,
	}
	return c
}
