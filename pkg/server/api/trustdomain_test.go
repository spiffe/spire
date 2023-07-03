package api_test

import (
	"net/url"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

var (
	td = spiffeid.RequireTrustDomainFromString("example.org")
)

func TestProtoToFederationRelationship(t *testing.T) {
	expectURL, err := url.Parse("https://some.url/path")
	require.NoError(t, err)
	proto := &types.FederationRelationship{
		TrustDomain:           "example.org",
		BundleEndpointUrl:     "https://some.url/path",
		BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
	}

	resp, err := api.ProtoToFederationRelationship(proto)
	require.NoError(t, err)

	expected := &datastore.FederationRelationship{
		TrustDomain:           td,
		BundleEndpointURL:     expectURL,
		BundleEndpointProfile: datastore.BundleEndpointWeb,
	}

	require.Equal(t, expected, resp)
}

func TestProtoToFederationRelationshipWithMask(t *testing.T) {
	expectURL, err := url.Parse("https://some.url/path")
	require.NoError(t, err)

	for _, tt := range []struct {
		name       string
		proto      *types.FederationRelationship
		mask       *types.FederationRelationshipMask
		expectResp *datastore.FederationRelationship
		expectErr  string
	}{
		{
			name: "HttpsWeb: no mask",
			proto: &types.FederationRelationship{
				TrustDomain:           "example.org",
				BundleEndpointUrl:     "https://some.url/path",
				BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
			},
			expectResp: &datastore.FederationRelationship{
				TrustDomain:           td,
				BundleEndpointURL:     expectURL,
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
		},
		{
			name: "HttpsWeb: mask all false",
			proto: &types.FederationRelationship{
				TrustDomain:           "example.org",
				BundleEndpointUrl:     "https://some.url/path",
				BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
			},
			expectResp: &datastore.FederationRelationship{
				TrustDomain:           td,
				BundleEndpointURL:     expectURL,
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
		},
		{
			name: "HttpsSpiffe: no mask",
			proto: &types.FederationRelationship{
				TrustDomain:       "example.org",
				BundleEndpointUrl: "https://some.url/path",
				BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
					HttpsSpiffe: &types.HTTPSSPIFFEProfile{
						EndpointSpiffeId: "spiffe://example.org/endpoint",
					},
				},
				TrustDomainBundle: &types.Bundle{
					TrustDomain: td.Name(),
				},
			},
			expectResp: &datastore.FederationRelationship{
				TrustDomain:           td,
				BundleEndpointURL:     expectURL,
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://example.org/endpoint"),
				TrustDomainBundle: &common.Bundle{
					TrustDomainId: "spiffe://example.org",
				},
			},
		},
		{
			name: "HttpsSpiffe: mask all false",
			proto: &types.FederationRelationship{
				TrustDomain:       "example.org",
				BundleEndpointUrl: "https://some.url/path",
				BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
					HttpsSpiffe: &types.HTTPSSPIFFEProfile{
						EndpointSpiffeId: "spiffe://example.org/endpoint",
					},
				},
				TrustDomainBundle: &types.Bundle{
					TrustDomain: td.Name(),
				},
			},
			mask: &types.FederationRelationshipMask{},
			expectResp: &datastore.FederationRelationship{
				TrustDomain: td,
			},
		},
		{
			name:      "no proto",
			expectErr: "missing federation relationship",
		},
		{
			name: "malformed trust domain",
			proto: &types.FederationRelationship{
				TrustDomain:           "no a td",
				BundleEndpointUrl:     "https://some.url/path",
				BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
			},
			expectErr: "failed to parse trust domain: trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
		},
		{
			name: "malformed BundleEndpointURL",
			proto: &types.FederationRelationship{
				TrustDomain:           "example.org",
				BundleEndpointUrl:     "!@#%^&^",
				BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
			},
			expectErr: "failed to parse bundle endpoint URL: parse",
		},
		{
			name: "malformed EndpointSpiffeId",
			proto: &types.FederationRelationship{
				TrustDomain:       "example.org",
				BundleEndpointUrl: "https://some.url/path",
				BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
					HttpsSpiffe: &types.HTTPSSPIFFEProfile{
						EndpointSpiffeId: "no an ID",
					},
				},
				TrustDomainBundle: &types.Bundle{
					TrustDomain: td.Name(),
				},
			},
			expectErr: "failed to parse endpoint SPIFFE ID:",
		},
		{
			name: "malformed Bundle",
			proto: &types.FederationRelationship{
				TrustDomain:       "example.org",
				BundleEndpointUrl: "https://some.url/path",
				BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
					HttpsSpiffe: &types.HTTPSSPIFFEProfile{
						EndpointSpiffeId: "spiffe://example.org/endpoint",
					},
				},
				TrustDomainBundle: &types.Bundle{
					TrustDomain: "no a td",
				},
			},
			expectErr: "failed to parse bundle: invalid trust domain: trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
		},
		{
			name: "no BundleEndpointProfile provided",
			proto: &types.FederationRelationship{
				TrustDomain:       "example.org",
				BundleEndpointUrl: "https://some.url/path",
			},
			expectErr: "unsupported bundle endpoint profile type:",
		},
		{
			name: "HttpsSpiffe: empty",
			proto: &types.FederationRelationship{
				TrustDomain:           "example.org",
				BundleEndpointUrl:     "https://some.url/path",
				BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{},
			},
			expectErr: "bundle endpoint profile does not contain \"HttpsSpiffe\"",
		},
		{
			name: "BundleEndpointUrl must start with https",
			proto: &types.FederationRelationship{
				TrustDomain:           "example.org",
				BundleEndpointUrl:     "some.url/path",
				BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
			},
			expectErr: "bundle endpoint URL must use the https scheme",
		},
		{
			name: "BundleEndpointUrl with user info",
			proto: &types.FederationRelationship{
				TrustDomain:           "example.org",
				BundleEndpointUrl:     "https://user:password@some.url/path",
				BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
			},
			expectErr: "bundle endpoint URL must not contain user info",
		},
		{
			name: "BundleEndpointUrl empty host",
			proto: &types.FederationRelationship{
				TrustDomain:           "example.org",
				BundleEndpointUrl:     "https://",
				BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
			},
			expectErr: "bundle endpoint URL must specify the host",
		},
		{
			name: "TrustDomainBundle has mismatched trust domain",
			proto: &types.FederationRelationship{
				TrustDomain:           "example.org",
				BundleEndpointUrl:     "https://example.org/bundle",
				BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
				TrustDomainBundle: &types.Bundle{
					TrustDomain: "some-other-domain.test",
				},
			},
			expectErr: `trust domain bundle ("some-other-domain.test") must match the trust domain of the federation relationship ("example.org")`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := api.ProtoToFederationRelationshipWithMask(tt.proto, tt.mask)
			if tt.expectErr != "" {
				spiretest.AssertErrorPrefix(t, err, tt.expectErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectResp, resp)
		})
	}
}

func TestFederationRelationshipToProto(t *testing.T) {
	endpointURL, err := url.Parse("https://some.url/path")
	require.NoError(t, err)

	for _, tt := range []struct {
		name        string
		fr          *datastore.FederationRelationship
		mask        *types.FederationRelationshipMask
		expectErr   string
		expectProto *types.FederationRelationship
	}{
		{
			name: "HttpsWeb: no mask",
			fr: &datastore.FederationRelationship{
				TrustDomain:           td,
				BundleEndpointURL:     endpointURL,
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
			expectProto: &types.FederationRelationship{
				TrustDomain:           "example.org",
				BundleEndpointUrl:     "https://some.url/path",
				BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
			},
		},
		{
			name: "HttpsWeb: mask all false",
			fr: &datastore.FederationRelationship{
				TrustDomain:           td,
				BundleEndpointURL:     endpointURL,
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
			mask: &types.FederationRelationshipMask{},
			expectProto: &types.FederationRelationship{
				TrustDomain: "example.org",
			},
		},
		{
			name: "HttpsSpiffe: no mask",
			fr: &datastore.FederationRelationship{
				TrustDomain:           td,
				BundleEndpointURL:     endpointURL,
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromPath(td, "/endpoint"),
				TrustDomainBundle: &common.Bundle{
					TrustDomainId: "example.org",
				},
			},
			expectProto: &types.FederationRelationship{
				TrustDomain:       "example.org",
				BundleEndpointUrl: "https://some.url/path",
				BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
					HttpsSpiffe: &types.HTTPSSPIFFEProfile{
						EndpointSpiffeId: "spiffe://example.org/endpoint",
					},
				},
				TrustDomainBundle: &types.Bundle{
					TrustDomain: "example.org",
				},
			},
		},
		{
			name: "HttpsSpiffe: mask all false",
			fr: &datastore.FederationRelationship{
				TrustDomain:           td,
				BundleEndpointURL:     endpointURL,
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromPath(td, "/endpoint"),
				TrustDomainBundle: &common.Bundle{
					TrustDomainId: "example.org",
				},
			},
			mask: &types.FederationRelationshipMask{},
			expectProto: &types.FederationRelationship{
				TrustDomain: "example.org",
			},
		},
		{
			name: "empty trustdomain",
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.TrustDomain{},
				BundleEndpointURL:     endpointURL,
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
			expectErr: "trust domain is required",
		},
		{
			name: "no BundleEndpointURL",
			fr: &datastore.FederationRelationship{
				TrustDomain:           td,
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
			expectErr: "bundle endpoint URL is required",
		},
		{
			name: "bundle has malformed trust domain",
			fr: &datastore.FederationRelationship{
				TrustDomain:           td,
				BundleEndpointURL:     endpointURL,
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromPath(td, "/endpoint"),
				TrustDomainBundle: &common.Bundle{
					TrustDomainId: "sparfe://example.org",
				},
			},
			expectErr: "invalid trust domain id: scheme is missing or invalid",
		},
		{
			name: "no BundleEndpointProvider provided",
			fr: &datastore.FederationRelationship{
				TrustDomain:       td,
				BundleEndpointURL: endpointURL,
				EndpointSPIFFEID:  spiffeid.RequireFromPath(td, "/endpoint"),
			},
			expectErr: "unsupported BundleEndpointProfile: ",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			proto, err := api.FederationRelationshipToProto(tt.fr, tt.mask)

			if tt.expectErr != "" {
				spiretest.AssertErrorPrefix(t, err, tt.expectErr)
				return
			}

			require.NoError(t, err)
			spiretest.RequireProtoEqual(t, tt.expectProto, proto)
		})
	}
}
