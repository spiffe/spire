package datastore

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/require"
)

func TestWithBundlePublisher(t *testing.T) {
	keyID1 := "key-id-1"
	keyID2 := "key-id-2"
	td := spiffeid.RequireTrustDomainFromString("spiffe://example.org")
	rootCA := testca.New(t, td).X509Authorities()[0]
	bundle1 := &common.Bundle{
		TrustDomainId:  td.IDString(),
		RootCas:        []*common.Certificate{{DerBytes: rootCA.Raw}},
		JwtSigningKeys: []*common.PublicKey{{Kid: keyID1, PkixBytes: []byte{}, NotAfter: 1000}},
	}
	bundle2 := &common.Bundle{
		TrustDomainId:  td.IDString(),
		RootCas:        []*common.Certificate{{DerBytes: rootCA.Raw}},
		JwtSigningKeys: []*common.PublicKey{{Kid: keyID2, PkixBytes: []byte{}, NotAfter: 2000}},
	}

	for _, tt := range []struct {
		name                  string
		assertCallingCallback func(ctx context.Context, t *testing.T, ds datastore.DataStore, wt *wrapperTest)
	}{
		{
			name: "AppendBundle",
			assertCallingCallback: func(ctx context.Context, t *testing.T, ds datastore.DataStore, wt *wrapperTest) {
				_, err := ds.AppendBundle(ctx, bundle2)
				require.NoError(t, err)
				require.True(t, wt.callbackCalled)
			},
		},
		{
			name: "PruneBundle",
			assertCallingCallback: func(ctx context.Context, t *testing.T, ds datastore.DataStore, wt *wrapperTest) {
				_, err := ds.PruneBundle(ctx, bundle2.TrustDomainId, time.Unix(1000, 0))
				require.NoError(t, err)
				require.True(t, wt.callbackCalled)
			},
		},
		{
			name: "RevokeX509CA",
			assertCallingCallback: func(ctx context.Context, t *testing.T, ds datastore.DataStore, wt *wrapperTest) {
				require.NoError(t, ds.TaintX509CA(ctx, bundle2.TrustDomainId, rootCA.PublicKey))

				// TaintX509CA should not call the callback function
				require.False(t, wt.callbackCalled)

				require.NoError(t, ds.RevokeX509CA(ctx, bundle2.TrustDomainId, rootCA.PublicKey))
				require.True(t, wt.callbackCalled)
			},
		},
		{
			name: "RevokeJWTKey",
			assertCallingCallback: func(ctx context.Context, t *testing.T, ds datastore.DataStore, wt *wrapperTest) {
				_, err := ds.TaintJWTKey(ctx, "spiffe://example.org", keyID2)
				require.NoError(t, err)

				// TaintJWTKey should not call the callback function
				require.False(t, wt.callbackCalled)

				_, err = ds.RevokeJWTKey(ctx, "spiffe://example.org", keyID2)
				require.NoError(t, err)
				require.True(t, wt.callbackCalled)
			},
		},
	} {
		tt := tt
		ctx := context.Background()
		t.Run(tt.name, func(t *testing.T) {
			var ds datastore.DataStore = fakedatastore.New(t)

			// We want to have at least two JWT signing keys so one can be
			// pruned.
			_, err := ds.CreateBundle(ctx, bundle1)
			require.NoError(t, err)
			_, err = ds.AppendBundle(ctx, bundle2)
			require.NoError(t, err)

			test := &wrapperTest{}
			ds = WithBundleUpdateCallback(ds, test.bundleUpdated)
			tt.assertCallingCallback(ctx, t, ds, test)
		})
	}
}

type wrapperTest struct {
	callbackCalled bool
}

func (w *wrapperTest) bundleUpdated() {
	w.callbackCalled = true
}
