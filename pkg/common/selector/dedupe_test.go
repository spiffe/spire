package selector

import (
	"math/rand"
	"testing"
	"time"

	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/assert"
)

func TestDedupe(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint // gosec: no need for cryptographic randomness here

	aa := &common.Selector{Type: "A", Value: "A"}
	ab := &common.Selector{Type: "A", Value: "B"}
	ba := &common.Selector{Type: "B", Value: "A"}

	slice := func(ss ...*common.Selector) []*common.Selector { return ss }

	// Empty slice
	assert.Equal(t, Dedupe(slice()), slice())

	// Slice of one
	assert.Equal(t, Dedupe(slice(aa)), slice(aa))

	// Two identical slices of one
	assert.Equal(t, Dedupe(slice(aa), slice(aa)), slice(aa))

	// Two different slices of one
	assert.Equal(t, Dedupe(slice(aa), slice(ab)), slice(aa, ab))

	// Same but in reverse order
	assert.Equal(t, Dedupe(slice(ab), slice(aa)), slice(aa, ab))

	// Three slices in any random order
	in := [][]*common.Selector{slice(ba), slice(aa), slice(ab)}
	r.Shuffle(len(in), func(i, j int) {
		in[i], in[j] = in[j], in[i]
	})
	assert.Equal(t, Dedupe(in...), slice(aa, ab, ba))
}
