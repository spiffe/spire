// The selector package exports functions useful for manipulating and generating
// spire selectors
package selector

import (
	"fmt"
	"strings"

	"github.com/spiffe/spire/proto/spire/common"
)

// Type and Value are delimited by a colon (:)
// e.g. "unix:uid:1000"
const Delimiter = ":"

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

func Validate(s *common.Selector) error {
	// Validate that the Type does not contain a colon (:) to prevent accidental misconfigurations
	// e.g. type="unix:user" value="root" is the invalid selector
	// and type="unix" value"user:root" is the valid selector
	if strings.Contains(s.Type, Delimiter) {
		return fmt.Errorf("selector type must not contain a colon; invalid selector type: %q", s.Type)
	}
	return nil
}
