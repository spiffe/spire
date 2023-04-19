package datastore

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakepubmanager"
	"github.com/stretchr/testify/require"
)

func TestWithBundlePublisher(t *testing.T) {
	pubManager := fakepubmanager.New()

	ds := WithBundleUpdateCallback(fakedatastore.New(t), pubManager.BundleUpdated)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, _ = ds.AppendBundle(ctx, nil)
	require.NoError(t, pubManager.WaitForUpdate(ctx))

	_, _ = ds.PruneBundle(ctx, "spiffe://example.org", time.Now())
	require.NoError(t, pubManager.WaitForUpdate(ctx))

	_ = ds.RevokeX509CA(ctx, "spiffe://example.org", nil)
	require.NoError(t, pubManager.WaitForUpdate(ctx))

	_, _ = ds.RevokeJWTKey(ctx, "spiffe://example.org", "keyID")
	require.NoError(t, pubManager.WaitForUpdate(ctx))
}
