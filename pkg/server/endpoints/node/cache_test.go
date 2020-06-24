package node

import (
	"testing"

	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
)

func TestFetchBundleCache(t *testing.T) {
	req := &datastore.FetchBundleRequest{TrustDomainId: "spiffe://domain.test"}
	bundle1 := &common.Bundle{TrustDomainId: "spiffe://domain.test", RefreshHint: 1}
	bundle2 := &common.Bundle{TrustDomainId: "spiffe://domain.test", RefreshHint: 2}
	ds := fakedatastore.New(t)
	clock := clock.NewMock(t)
	cache := newDatastoreCache(ds, clock)

	// Assert bundle is missing
	resp, err := cache.FetchBundle(context.Background(), req)
	require.NoError(t, err)
	require.Empty(t, resp.Bundle)

	// Add bundle
	_, err = ds.SetBundle(context.Background(), &datastore.SetBundleRequest{
		Bundle: bundle1,
	})
	require.NoError(t, err)

	// Assert that we didn't cache the bundle miss and that the newly added
	// bundle is there
	resp, err = cache.FetchBundle(context.Background(), req)
	require.NoError(t, err)
	spiretest.RequireProtoEqual(t, bundle1, resp.Bundle)

	// Change bundle
	_, err = ds.SetBundle(context.Background(), &datastore.SetBundleRequest{
		Bundle: bundle2,
	})
	require.NoError(t, err)

	// Assert bundle contents unchanged since cache is still valid
	resp, err = cache.FetchBundle(context.Background(), req)
	require.NoError(t, err)
	spiretest.RequireProtoEqual(t, bundle1, resp.Bundle)

	// Invalidate cache and assert bundle contents changed
	clock.Add(datastoreCacheExpiry)
	resp, err = cache.FetchBundle(context.Background(), req)
	require.NoError(t, err)
	spiretest.RequireProtoEqual(t, bundle2, resp.Bundle)

	// Assert bundle contents unchanged since cache is still valid
	resp, err = cache.FetchBundle(context.Background(), req)
	require.NoError(t, err)
	spiretest.RequireProtoEqual(t, bundle2, resp.Bundle)
}
