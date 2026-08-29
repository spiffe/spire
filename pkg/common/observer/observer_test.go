package observer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPropertyStreamObservesUpdate(t *testing.T) {
	property := NewProperty("initial")
	stream := property.Observe()

	assert.Equal(t, "initial", property.Value())
	assert.Equal(t, "initial", stream.Value())
	assert.False(t, stream.HasNext())

	property.Update("updated")

	requireChange(t, stream.Changes())
	assert.True(t, stream.HasNext())
	assert.Equal(t, "updated", stream.Next())
	assert.Equal(t, "updated", stream.Value())
	assert.Equal(t, "updated", property.Value())
	assert.False(t, stream.HasNext())
}

func TestWaitNextBlocksUntilUpdate(t *testing.T) {
	property := NewProperty("initial")
	stream := property.Observe()

	ready := make(chan struct{})
	result := make(chan any, 1)
	go func() {
		close(ready)
		result <- stream.WaitNext()
	}()

	<-ready
	select {
	case value := <-result:
		t.Fatalf("WaitNext returned before update: %v", value)
	case <-time.After(20 * time.Millisecond):
	}

	property.Update("updated")

	select {
	case value := <-result:
		assert.Equal(t, "updated", value)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for WaitNext")
	}
}

func TestStreamDeliversSequentialUpdatesInOrder(t *testing.T) {
	property := NewProperty(0)
	stream := property.Observe()

	property.Update(1)
	property.Update(2)
	property.Update(3)

	for _, expected := range []int{1, 2, 3} {
		require.True(t, stream.HasNext())
		requireChange(t, stream.Changes())
		assert.Equal(t, expected, stream.Next())
		assert.Equal(t, expected, stream.Value())
	}
	assert.False(t, stream.HasNext())
	requireNoChange(t, stream.Changes())
}

func TestIndependentStreamsObserveCurrentValue(t *testing.T) {
	property := NewProperty("initial")
	streamA := property.Observe()

	property.Update("current")
	streamB := property.Observe()

	assert.Equal(t, "initial", streamA.Value())
	assert.True(t, streamA.HasNext())
	assert.Equal(t, "current", streamB.Value())
	assert.False(t, streamB.HasNext())

	assert.Equal(t, "current", streamA.Next())
	property.Update("next")

	assert.Equal(t, "next", streamA.Next())
	assert.Equal(t, "next", streamB.Next())
	assert.Equal(t, "next", streamA.Value())
	assert.Equal(t, "next", streamB.Value())
}

func TestStreamCloneCopiesCursor(t *testing.T) {
	property := NewProperty("initial")
	stream := property.Observe()

	property.Update("first")
	clone := stream.Clone()

	assert.Equal(t, "initial", stream.Value())
	assert.Equal(t, "initial", clone.Value())
	assert.Equal(t, "first", stream.Next())
	assert.Equal(t, "first", clone.Next())

	property.Update("second")

	assert.Equal(t, "second", stream.Next())
	assert.Equal(t, "second", clone.Next())
}

func requireChange(t *testing.T, changes chan struct{}) {
	t.Helper()

	select {
	case <-changes:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for change")
	}
}

func requireNoChange(t *testing.T, changes chan struct{}) {
	t.Helper()

	select {
	case <-changes:
		t.Fatal("unexpected change")
	case <-time.After(20 * time.Millisecond):
	}
}
