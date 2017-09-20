package selector

import (
	"bytes"
	"sort"

	"github.com/spiffe/spire/proto/common"
)

type Set []*Selector

func NewSet(c []*common.Selector) Set {
	set := Set{}
	for _, cs := range c {
		s := &Selector{
			Type:  cs.Type,
			Value: cs.Value,
		}
		set = append(set, s)
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

func (s Set) String() string {
	var b bytes.Buffer

	b.WriteString("[")

	if len(s) > 0 {
		// Preceding space starts after first element
		b.WriteString(s[0].Type)
		b.WriteString(":")
		b.WriteString(s[0].Value)
		for _, selector := range s[1:] {
			b.WriteString(" ")
			b.WriteString(selector.Type)
			b.WriteString(":")
			b.WriteString(selector.Value)
		}
	}

	b.WriteString("]")
	return b.String()
}

func (s Set) Sort() {
	sort.Sort(s)
}

// Satisfy the sort interface
func (s Set) Len() int      { return len(s) }
func (s Set) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s Set) Less(i, j int) bool {
	if s[i].Type != s[j].Type {
		return s[i].Type < s[j].Type
	} else {
		return s[i].Value < s[j].Value
	}
}
