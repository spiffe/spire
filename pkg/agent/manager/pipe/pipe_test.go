package pipe_test

import (
	"testing"

	"github.com/spiffe/spire/pkg/agent/manager/pipe"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/assert"
)

func TestBufferedPipe(t *testing.T) {
	entry1 := &common.RegistrationEntry{SpiffeId: "spiffe://example.org/foo"}
	entry2 := &common.RegistrationEntry{SpiffeId: "spiffe://example.org/bar"}
	entry3 := &common.RegistrationEntry{SpiffeId: "spiffe://example.org/baz"}
	entry4 := &common.RegistrationEntry{SpiffeId: "spiffe://example.org/nah"}

	in, out := pipe.BufferedPipe(2)
	in.Push(&pipe.SVIDUpdate{Entry: entry1})
	in.Push(&pipe.SVIDUpdate{Entry: entry2})
	in.Push(&pipe.SVIDUpdate{Entry: entry3})
	// Push nil must be excluded
	in.Push(nil)
	in.Close()
	in.Push(&pipe.SVIDUpdate{Entry: entry4})

	update, ok := <-out.GetUpdate()
	if assert.True(t, ok, "has update") {
		assert.Equal(t, "spiffe://example.org/bar", update.Entry.SpiffeId)
	}

	update, ok = <-out.GetUpdate()
	if assert.True(t, ok, "has update") {
		assert.Equal(t, "spiffe://example.org/baz", update.Entry.SpiffeId)
	}

	update, ok = <-out.GetUpdate()
	if ok {
		t.Fatalf("update %+v not expected", update)
	}
}
