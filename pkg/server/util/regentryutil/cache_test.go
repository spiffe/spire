package regentryutil

import (
	"testing"
	"time"

	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/stretchr/testify/require"
)

func TestFetchSVIDCache(t *testing.T) {
	clk := clock.NewMock(t)
	ttl := time.Minute
	cache, err := NewFetchX509SVIDCache(10)
	require.NoError(t, err)
	cache.TimeNow = clk.Now

	key := "spiffe://example.org/root"
	oneID := "spiffe://example.org/1"

	entries := []*common.RegistrationEntry{
		&common.RegistrationEntry{
			ParentId: key,
			SpiffeId: oneID,
		},
	}

	// cache is empty
	val, ok := cache.Get(key)
	require.Empty(t, val)
	require.False(t, ok)

	cache.AddWithExpire(key, entries, ttl)

	// cached value exists
	val, ok = cache.Get(key)
	require.Equal(t, entries, val)
	require.True(t, ok)

	clk.Add(ttl - time.Millisecond)

	// cached value still exists after some time
	val, ok = cache.Get(key)
	require.Equal(t, entries, val)
	require.True(t, ok)

	clk.Add(2 * time.Millisecond)

	// cached value disappears after TTL
	val, ok = cache.Get(key)
	require.Empty(t, val)
	require.False(t, ok)

	// verify its actually removed from internal cache
	ifc, ok := cache.Cache.Get(key)
	require.Nil(t, ifc)
	require.False(t, ok)
}
