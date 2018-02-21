package selector

import (
	"bytes"

	"github.com/spiffe/spire/proto/common"
)

type Set map[string]*Selector

func NewSet(c []*common.Selector) Set {
	set := Set{}
	for _, cs := range c {
		s := &Selector{
			Type:  cs.Type,
			Value: cs.Value,
		}
		set[deriveKey(s)] = s
	}

	return set
}

func (s Set) Raw() []*common.Selector {
	c := []*common.Selector{}
	for _, selector := range s {
		cs := &common.Selector{
			Type:  selector.Type,
			Value: selector.Value,
		}
		c = append(c, cs)
	}

	return c
}

func (s Set) Power() <-chan Set {
	return PowerSet(s)
}

func (s Set) Equal(otherSet Set) bool {
	return EqualSet(s, otherSet)
}

func (s Set) Includes(selector *Selector) bool {
	return Includes(s, selector)
}

func (s Set) IncludesSet(s2 Set) bool {
	return IncludesSet(s, s2)
}

func (s Set) String() string {
	var b bytes.Buffer

	b.WriteString("[")

	if len(s) > 0 {

		i := 0
		for _, selector := range s {
			if i > 0 {
				b.WriteString(" ")
			}
			b.WriteString(selector.Type)
			b.WriteString(":")
			b.WriteString(selector.Value)
			i++
		}
	}

	b.WriteString("]")
	return b.String()
}
