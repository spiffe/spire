package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/keyvalue"
	"github.com/stretchr/testify/require"
)

var (
	kind  = "kind"
	key   = "key"
	data1 = []byte("data1")
	data2 = []byte("data2")
	data3 = []byte("data3")
)

func Test(t *testing.T, openStore func(ctx context.Context, t *testing.T, nowFn func() time.Time) keyvalue.Store) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var err error

	now := time.Now()
	s := openStore(ctx, t, func() time.Time {
		return now
	})

	r1, err := s.Get(ctx, kind, key)
	require.True(t, errors.Is(err, keyvalue.ErrNotFound), "unexpected error %q", err)
	err = s.Create(ctx, kind, key, data1)
	require.NoError(t, err)
	r1, err = s.Get(ctx, kind, key)
	require.NoError(t, err)
	err = s.Create(ctx, kind, key, data1)
	require.True(t, errors.Is(err, keyvalue.ErrExists), "unexpected error %q", err)

	err = s.Update(ctx, kind, key, data2, r1.Revision+1)
	require.True(t, errors.Is(err, keyvalue.ErrConflict), "unexpected error %q", err)

	now = now.Add(time.Second)
	err = s.Update(ctx, kind, key, data2, r1.Revision)
	require.NoError(t, err)
	r2, err := s.Get(ctx, kind, key)
	require.NoError(t, err)
	require.Equal(t, r1.CreatedAt, r2.CreatedAt)
	require.NotEqual(t, r1.UpdatedAt, r2.UpdatedAt)

	now = now.Add(time.Second)
	err = s.Replace(ctx, kind, key, data3)
	require.NoError(t, err)
	r3, err := s.Get(ctx, kind, key)
	require.NoError(t, err)
	require.Equal(t, r1.CreatedAt, r3.CreatedAt)
	require.NotEqual(t, r1.UpdatedAt, r3.UpdatedAt)
	require.Equal(t, r2.CreatedAt, r3.CreatedAt)
	require.NotEqual(t, r2.UpdatedAt, r3.UpdatedAt)

	err = s.Delete(ctx, kind, key)
	require.NoError(t, err)
	_, err = s.Get(ctx, kind, key)
	require.True(t, errors.Is(err, keyvalue.ErrNotFound), "unexpected error %q", err)
	err = s.Delete(ctx, kind, key)
	require.True(t, errors.Is(err, keyvalue.ErrNotFound), "unexpected error %q", err)
}
