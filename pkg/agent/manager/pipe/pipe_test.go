package pipe_test

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/manager/pipe"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	common_catalog "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBufferedPipe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	entry1 := &common.RegistrationEntry{SpiffeId: "spiffe://example.org/foo"}
	entry2 := &common.RegistrationEntry{SpiffeId: "spiffe://example.org/bar"}
	entry3 := &common.RegistrationEntry{SpiffeId: "spiffe://example.org/baz"}

	in, out := pipe.BufferedPipe(ctx, 2)
	in.Push(&pipe.SVIDUpdate{Entry: entry1})
	in.Push(&pipe.SVIDUpdate{Entry: entry2})
	// Push nil must be excluded
	in.Push(nil)
	in.Close()
	in.Push(&pipe.SVIDUpdate{Entry: entry3})

	update, ok := <-out.GetUpdate()
	if assert.True(t, ok, "has update") {
		assert.Equal(t, "spiffe://example.org/foo", update.Entry.SpiffeId)
	}

	update, ok = <-out.GetUpdate()
	if assert.True(t, ok, "has update") {
		assert.Equal(t, "spiffe://example.org/bar", update.Entry.SpiffeId)
	}

	update, ok = <-out.GetUpdate()
	if ok {
		t.Fatalf("update %+v not expected", update)
	}
}

func TestCreateStorePipes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	store1 := &fakeSVIDStore{
		name: "store1",
	}
	store2 := &fakeSVIDStore{
		name: "store2",
	}

	svidStores := []catalog.SVIDStores{
		{PluginInfo: store1, SVIDStore: store1},
		{PluginInfo: store2, SVIDStore: store2},
	}

	resp := pipe.CreateStorePipes(ctx, svidStores)
	defer resp.Close()

	// Verify store map contains expected pipes
	require.Len(t, resp, 2)

	s1 := resp["store1"]
	require.Equal(t, "store1", s1.Store.Name())

	s2 := resp["store2"]
	require.Equal(t, "store2", s2.Store.Name())

	// Get all pipes In
	pipesIn := resp.PipeIns()
	require.Len(t, pipesIn, 2)

	// Push a pipe to In and verify out contains expected value
	update := &pipe.SVIDUpdate{Entry: &common.RegistrationEntry{SpiffeId: "spiffe://example.org/foo"}}
	pipesIn["store1"].Push(update)
	out, ok := <-s1.Out.GetUpdate()
	require.True(t, ok)
	require.Equal(t, update, out)

	// Push a pipe to In and verify out contains expected value
	update = &pipe.SVIDUpdate{Entry: &common.RegistrationEntry{SpiffeId: "spiffe://example.org/bar"}}
	pipesIn["store2"].Push(update)
	out, ok = <-s2.Out.GetUpdate()
	require.True(t, ok)
	require.Equal(t, update, out)
}

type fakeSVIDStore struct {
	svidstore.SVIDStore
	common_catalog.PluginInfo

	name string
}

func (f *fakeSVIDStore) Name() string {
	return f.name
}
