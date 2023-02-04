package bundle

import (
	"context"
	"testing"

	"github.com/spiffe/spire/test/clock"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchBundleX509(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("spiffe://domain.test")
	ca := testca.New(t, td)
	certs1, _ := ca.CreateX509Certificate()
	certs2, _ := ca.CreateX509Certificate()

	bundleX509Response := x509bundle.FromX509Authorities(td, certs1)
	updatedBundleX509Response := x509bundle.FromX509Authorities(td, certs2)
	bundle1 := &common.Bundle{TrustDomainId: "spiffe://domain.test", RefreshHint: 1, RootCas: []*common.Certificate{{DerBytes: certs1[0].Raw}}}
	bundle2 := &common.Bundle{TrustDomainId: "spiffe://domain.test", RefreshHint: 2, RootCas: []*common.Certificate{{DerBytes: certs2[0].Raw}}}
	ds := fakedatastore.New(t)
	clock := clock.NewMock(t)
	cache := NewCache(ds, clock)
	ctx := context.Background()

	// Assert bundle is missing
	bundleX509, err := cache.FetchBundleX509(ctx, td)
	require.NoError(t, err)
	require.Nil(t, bundleX509)

	// Add bundle
	_, err = ds.SetBundle(ctx, bundle1)
	require.NoError(t, err)

	// Assert that we didn't cache the bundle miss and that the newly added
	// bundle is there
	bundleX509, err = cache.FetchBundleX509(ctx, td)
	require.NoError(t, err)
	assert.Equal(t, bundleX509Response, bundleX509)

	// Change bundle
	_, err = ds.SetBundle(context.Background(), bundle2)
	require.NoError(t, err)

	// Assert bundle contents unchanged since cache is still valid
	bundleX509, err = cache.FetchBundleX509(ctx, td)
	require.NoError(t, err)
	assert.Equal(t, bundleX509Response, bundleX509)

	// If caches expires by time, FetchBundleX509 must fetch a fresh bundle
	clock.Add(cacheExpiry)
	bundleX509, err = cache.FetchBundleX509(ctx, td)
	require.NoError(t, err)
	assert.Equal(t, updatedBundleX509Response, bundleX509)

	// If caches expires by time, but bundle didn't change, FetchBundleX509 must fetch a fresh bundle
	clock.Add(cacheExpiry)
	bundleX509, err = cache.FetchBundleX509(ctx, td)
	require.NoError(t, err)
	assert.Equal(t, updatedBundleX509Response, bundleX509)
}
