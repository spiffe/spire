package api_test

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

func TestBundleToProto(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	for _, tt := range []struct {
		name         string
		bundle       *common.Bundle
		expectBundle *types.Bundle
		expectError  string
	}{
		{
			name: "success",
			bundle: &common.Bundle{
				TrustDomainId: td.String(),
				RefreshHint:   10,
				RootCas:       []*common.Certificate{{DerBytes: []byte("cert-bytes")}},
				JwtSigningKeys: []*common.PublicKey{
					{
						Kid:       "key-id-1",
						NotAfter:  1590514224,
						PkixBytes: []byte("pkix key"),
					},
				},
			},
			expectBundle: &types.Bundle{
				TrustDomain: td.String(),
				RefreshHint: 10,
				X509Authorities: []*types.X509Certificate{
					{
						Asn1: []byte("cert-bytes"),
					},
				},
				JwtAuthorities: []*types.JWTKey{
					{

						PublicKey: []byte("pkix key"),
						KeyId:     "key-id-1",
						ExpiresAt: 1590514224,
					},
				},
			},
		}, {
			name:        "no bundle",
			expectError: "no bundle provided",
		}, {
			name: "invalid trust domain",
			bundle: &common.Bundle{
				TrustDomainId: "invaid TD",
			},
			expectError: `spiffeid: unable to parse: parse spiffe://invaid TD: invalid character " " in host name`,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			bundle, err := api.BundleToProto(tt.bundle)

			if tt.expectError != "" {
				require.EqualError(t, err, tt.expectError)
				require.Nil(t, bundle)
				return
			}

			require.NoError(t, err)
			spiretest.AssertProtoEqual(t, tt.expectBundle, bundle)
		})
	}
}
