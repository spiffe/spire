package identityprovider

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	identityproviderv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/identityprovider/v1"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	td = spiffeid.RequireTrustDomainFromString("domain.test")

	privateKey, _ = pemutil.ParsePrivateKey([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiRwh3OhH038SIr6M
ksd9t4OFaYrOVSm0UrCA3c2ou3ihRANCAAQ5SCPTyVgLgzamI5X+iVM7jYmAvyLx
T9/3uGMibjwZ41KKO09baULXYYG/RW+zv+Mzz+DD2LGveAOx28dcQTaK
-----END PRIVATE KEY-----
`))
)

func TestFetchX509IdentityFailsIfDepsUnset(t *testing.T) {
	hs := New(Config{
		TrustDomain: td,
	})

	t.Run("v1", func(t *testing.T) {
		resp, err := hs.V1().FetchX509Identity(context.Background(), &identityproviderv1.FetchX509IdentityRequest{})
		st := status.Convert(err)
		assert.Equal(t, "IdentityProvider host service has not been initialized", st.Message())
		assert.Equal(t, codes.FailedPrecondition, st.Code())
		assert.Nil(t, resp)
	})
}

func TestFetchX509IdentitySuccess(t *testing.T) {
	bundleV0 := &common.Bundle{
		TrustDomainId: "spiffe://domain.test",
	}

	bundleV1 := &plugintypes.Bundle{
		TrustDomain: "domain.test",
	}

	ds := fakedatastore.New(t)
	_, err := ds.CreateBundle(context.Background(), bundleV0)
	require.NoError(t, err)

	hs := New(Config{
		TrustDomain: td,
	})

	certChain := []*x509.Certificate{
		{Raw: []byte{1}},
		{Raw: []byte{2}},
	}

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	err = hs.SetDeps(Deps{
		DataStore: ds,
		X509IdentityFetcher: X509IdentityFetcherFunc(func(context.Context) (*X509Identity, error) {
			return &X509Identity{
				CertChain:  certChain,
				PrivateKey: privateKey,
			}, nil
		}),
	})
	require.NoError(t, err)

	t.Run("v1", func(t *testing.T) {
		resp, err := hs.V1().FetchX509Identity(context.Background(), &identityproviderv1.FetchX509IdentityRequest{})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.Identity)
		require.Equal(t, [][]byte{{1}, {2}}, resp.Identity.CertChain)
		require.Equal(t, privateKeyBytes, resp.Identity.PrivateKey)
		spiretest.RequireProtoEqual(t, bundleV1, resp.Bundle)
	})
}
