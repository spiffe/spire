package selector

import (
	"bytes"

	"github.com/spiffe/spire/proto/common"
)

type Set interface {
	Raw() []*common.Selector
	Array() []*Selector
	Power() <-chan Set
	Equal(otherSet Set) bool
	Includes(selector *Selector) bool
	IncludesSet(s2 Set) bool
	Add(selector *Selector)
	Remove(selector *Selector) *Selector
	String() string
	Size() int
}

type set map[Selector]*Selector

func NewSet(selectors ...*Selector) Set {
	set := set{}
	for _, cs := range selectors {
		set.Add(cs)
	}
	return &set
}

func NewSetFromRaw(c []*common.Selector) Set {
	set := set{}
	for _, cs := range c {
		s := &Selector{
			Type:  cs.Type,
			Value: cs.Value,
		}
		set.Add(s)
	}

	return &set
}

func (s *set) Raw() []*common.Selector {
	c := []*common.Selector{}
	for _, selector := range *s {
		cs := &common.Selector{
			Type:  selector.Type,
			Value: selector.Value,
		}
		c = append(c, cs)
	}

	return c
}

// Array returns an array with the elements of the set in any order.
func (s *set) Array() []*Selector {
	c := []*Selector{}
	for _, selector := range *s {
		c = append(c, selector)
	}
	return c
}

func (s *set) Power() <-chan Set {
	return PowerSet(s)
}

func (s *set) Equal(otherSet Set) bool {
	return EqualSet(s, otherSet.(*set))
}

func (s *set) Includes(selector *Selector) bool {
	return Includes(s, selector)
}

func (s *set) IncludesSet(s2 Set) bool {
	return IncludesSet(s, s2.(*set))
}

func (s *set) Add(selector *Selector) {
	(*s)[*selector] = selector
}

func (s *set) Remove(selector *Selector) *Selector {
	key := *selector
	if removed, ok := (*s)[key]; ok {
		delete(*s, key)
		return removed
	}
	return nil
}

func (s *set) Size() int {
	return len(*s)
}

func (s *set) String() string {
	var b bytes.Buffer

	b.WriteString("[")

	if len(*s) > 0 {

		i := 0
		for _, selector := range *s {
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
