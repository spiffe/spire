package dscache

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestFetchBundleCache(t *testing.T) {
	td := "spiffe://domain.test"
	bundle1 := &common.Bundle{TrustDomainId: "spiffe://domain.test", RefreshHint: 1}
	bundle2 := &common.Bundle{TrustDomainId: "spiffe://domain.test", RefreshHint: 2}
	ds := fakedatastore.New(t)
	clock := clock.NewMock(t)
	cache := New(ds, clock)
	ctxWithCache := WithCache(context.Background())
	ctxWithoutCache := context.Background()

	// Assert bundle is missing
	bundle, err := cache.FetchBundle(ctxWithCache, td)
	require.NoError(t, err)
	require.Nil(t, bundle)

	// Add bundle
	_, err = ds.SetBundle(ctxWithCache, bundle1)
	require.NoError(t, err)

	// Assert that we didn't cache the bundle miss and that the newly added
	// bundle is there
	bundle, err = cache.FetchBundle(ctxWithCache, td)
	require.NoError(t, err)
	spiretest.RequireProtoEqual(t, bundle1, bundle)

	// Change bundle
	_, err = ds.SetBundle(context.Background(), bundle2)
	require.NoError(t, err)

	// Assert bundle contents unchanged since cache is still valid
	bundle, err = cache.FetchBundle(ctxWithCache, td)
	require.NoError(t, err)
	spiretest.RequireProtoEqual(t, bundle1, bundle)

	// If caches expires by time, FetchBundle must fetch a fresh bundle
	clock.Add(datastoreCacheExpiry)
	bundle, err = cache.FetchBundle(ctxWithCache, td)
	require.NoError(t, err)
	spiretest.RequireProtoEqual(t, bundle2, bundle)

	// Change bundle
	_, err = ds.SetBundle(context.Background(), bundle1)
	require.NoError(t, err)

	// If a context without cache is used, FetchBundle must fetch a fresh bundle
	bundle, err = cache.FetchBundle(ctxWithoutCache, td)
	require.NoError(t, err)
	spiretest.RequireProtoEqual(t, bundle1, bundle)

	bundle, err = cache.FetchBundle(ctxWithCache, td)
	require.NoError(t, err)
	spiretest.RequireProtoEqual(t, bundle1, bundle)
}

func TestBundleInvalidations(t *testing.T) {
	td := "spiffe://domain.test"
	bundle1, bundle2 := getBundles(t, "spiffe://domain.test")

	for _, tt := range []struct {
		name             string
		invalidatingFunc func(cache *DatastoreCache)
		dsFailure        bool
	}{
		{
			name: "UpdateBundle invalidates cache if succeeds",
			invalidatingFunc: func(cache *DatastoreCache) {
				_, _ = cache.UpdateBundle(context.Background(), bundle1, nil)
			},
		},
		{
			name:      "UpdateBundle keeps cache if fails",
			dsFailure: true,
			invalidatingFunc: func(cache *DatastoreCache) {
				_, _ = cache.UpdateBundle(context.Background(), bundle1, nil)
			},
		},
		{
			name: "AppendBundle invalidates cache if succeeds",
			invalidatingFunc: func(cache *DatastoreCache) {
				_, _ = cache.AppendBundle(context.Background(), bundle1)
			},
		},
		{
			name:      "AppendBundle keeps cache if fails",
			dsFailure: true,
			invalidatingFunc: func(cache *DatastoreCache) {
				_, _ = cache.AppendBundle(context.Background(), bundle1)
			},
		},
		{
			name: "PruneBundle invalidates cache if succeeds",
			invalidatingFunc: func(cache *DatastoreCache) {
				_, _ = cache.PruneBundle(context.Background(), td, time.Now().Add(-time.Hour))
			},
		},
		{
			name:      "PruneBundle keeps cache if fails",
			dsFailure: true,
			invalidatingFunc: func(cache *DatastoreCache) {
				_, _ = cache.PruneBundle(context.Background(), td, time.Now())
			},
		},
		{
			name: "DeleteBundle invalidates cache if succeeds",
			invalidatingFunc: func(cache *DatastoreCache) {
				_ = cache.DeleteBundle(context.Background(), td, datastore.Restrict)
			},
		},
		{
			name:      "DeleteBundle keeps cache if fails",
			dsFailure: true,
			invalidatingFunc: func(cache *DatastoreCache) {
				_ = cache.DeleteBundle(context.Background(), td, datastore.Restrict)
			},
		},
		{
			name: "SetBundle invalidates cache if succeeds",
			invalidatingFunc: func(cache *DatastoreCache) {
				_, _ = cache.SetBundle(context.Background(), bundle1)
			},
		},
		{
			name:      "SetBundle keeps cache if fails",
			dsFailure: true,
			invalidatingFunc: func(cache *DatastoreCache) {
				_, _ = cache.SetBundle(context.Background(), bundle1)
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Create datastore and cache
			ds := fakedatastore.New(t)
			cache := New(ds, clock.NewMock(t))
			ctxWithCache := WithCache(context.Background())

			// Add bundle (bundle1)
			_, err := ds.SetBundle(context.Background(), bundle1)
			require.NoError(t, err)

			// Make an initial fetch call to store the bundle in cache
			_, err = cache.FetchBundle(context.Background(), td)
			require.NoError(t, err)

			// Run the function that invalidates the bundle (Prune, Append, etc)
			// (which may or not fail according to dsFailure flag)
			if tt.dsFailure {
				ds.SetNextError(fmt.Errorf("failure"))
			}
			tt.invalidatingFunc(cache)

			// Change the bundle (bundle1 -> bundle2)
			_, err = ds.SetBundle(context.Background(), bundle2)
			require.NoError(t, err)

			// If invalidatingFunc fails, we keep the current cache value,
			// next call to FetchBundle should return bundle1
			if tt.dsFailure {
				bundle, err := cache.FetchBundle(ctxWithCache, td)
				require.NoError(t, err)
				spiretest.RequireProtoEqual(t, bundle1, bundle)
				return
			}

			// If invalidatingFunc succeeds, we invalidate the current cache
			// value, next call to FetchBundle should return the updated
			// bundle (bundle2)
			bundle, err := cache.FetchBundle(ctxWithCache, td)
			require.NoError(t, err)
			spiretest.RequireProtoEqual(t, bundle2, bundle)
		})
	}
}

// getBundles returns two different bundles with the same trust domain.
func getBundles(t *testing.T, td string) (*common.Bundle, *common.Bundle) {
	roots, keys := getRoots(t, td), getKeys(t)
	bundle1 := &common.Bundle{
		TrustDomainId:  td,
		RefreshHint:    1,
		SequenceNumber: 2,
		RootCas:        roots,
		JwtSigningKeys: keys,
	}

	bundle2 := proto.Clone(bundle1).(*common.Bundle)
	bundle2.RefreshHint = 2
	bundle2.SequenceNumber = 5

	return bundle1, bundle2
}

func getRoots(t *testing.T, td string) []*common.Certificate {
	ca := testca.New(t, spiffeid.RequireTrustDomainFromString(td))
	return []*common.Certificate{
		{
			DerBytes: ca.X509Authorities()[0].Raw,
		},
	}
}

func getKeys(t *testing.T) []*common.PublicKey {
	pkixBytes, err := base64.StdEncoding.DecodeString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYSlUVLqTD8DEnA4F1EWMTf5RXc5lnCxw+5WKJwngEL3rPc9i4Tgzz9riR3I/NiSlkgRO1WsxBusqpC284j9dXA==")
	require.NoError(t, err)
	return []*common.PublicKey{
		{
			PkixBytes: pkixBytes,
			Kid:       "kid",
			NotAfter:  time.Now().Unix(),
		},
	}
}
