package federation

import (
	"fmt"
	"testing"

	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestListHelp(t *testing.T) {
	test := setupTest(t, newListCommand)
	test.client.Help()

	require.Equal(t, listUsage, test.stderr.String())
}

func TestListSynopsis(t *testing.T) {
	test := setupTest(t, newListCommand)
	require.Equal(t, "Lists all dynamic federation relationships", test.client.Synopsis())
}

func TestList(t *testing.T) {
	federation1 := &types.FederationRelationship{
		TrustDomain:           "foh.test",
		BundleEndpointUrl:     "https://foo.test/endpoint",
		BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
	}

	federation2 := &types.FederationRelationship{
		TrustDomain:       "bar.test",
		BundleEndpointUrl: "https://bar.test/endpoint",
		BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
			HttpsSpiffe: &types.HTTPSSPIFFEProfile{
				EndpointSpiffeId: "spiffe://bar.test/id",
			},
		},
		TrustDomainBundle: &types.Bundle{TrustDomain: "bar.test"},
	}
	federation3 := &types.FederationRelationship{
		TrustDomain:       "baz.test",
		BundleEndpointUrl: "https://baz.test/endpoint",
		BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
			HttpsSpiffe: &types.HTTPSSPIFFEProfile{
				EndpointSpiffeId: "spiffe://baz.test/id",
			},
		},
	}

	for _, tt := range []struct {
		name string
		args []string

		expectListReq *trustdomainv1.ListFederationRelationshipsRequest
		listResp      *trustdomainv1.ListFederationRelationshipsResponse

		serverErr error

		expectOutPretty string
		expectOutJSON   string
		expectErr       string
	}{
		{
			name:            "no federations",
			expectListReq:   &trustdomainv1.ListFederationRelationshipsRequest{},
			listResp:        &trustdomainv1.ListFederationRelationshipsResponse{},
			expectOutPretty: "Found 0 federation relationships\n",
			expectOutJSON: `{
  "federation_relationships": [],
  "next_page_token": ""
}`,
		},
		{
			name:          "single federation",
			expectListReq: &trustdomainv1.ListFederationRelationshipsRequest{},
			listResp: &trustdomainv1.ListFederationRelationshipsResponse{
				FederationRelationships: []*types.FederationRelationship{federation1},
			},
			expectOutPretty: `Found 1 federation relationship

Trust domain              : foh.test
Bundle endpoint URL       : https://foo.test/endpoint
Bundle endpoint profile   : https_web
`,
			expectOutJSON: `{
  "federation_relationships": [
    {
      "trust_domain": "foh.test",
      "bundle_endpoint_url": "https://foo.test/endpoint",
      "https_web": {}
    }
  ],
  "next_page_token": ""
}`,
		},
		{
			name:          "multiple federations",
			expectListReq: &trustdomainv1.ListFederationRelationshipsRequest{},
			listResp: &trustdomainv1.ListFederationRelationshipsResponse{
				FederationRelationships: []*types.FederationRelationship{
					federation1,
					federation2,
					federation3,
				},
			},
			expectOutPretty: `Found 3 federation relationships

Trust domain              : foh.test
Bundle endpoint URL       : https://foo.test/endpoint
Bundle endpoint profile   : https_web

Trust domain              : bar.test
Bundle endpoint URL       : https://bar.test/endpoint
Bundle endpoint profile   : https_spiffe
Endpoint SPIFFE ID        : spiffe://bar.test/id

Trust domain              : baz.test
Bundle endpoint URL       : https://baz.test/endpoint
Bundle endpoint profile   : https_spiffe
Endpoint SPIFFE ID        : spiffe://baz.test/id
`,
			expectOutJSON: `{
  "federation_relationships": [
    {
      "trust_domain": "foh.test",
      "bundle_endpoint_url": "https://foo.test/endpoint",
      "https_web": {}
    },
    {
      "trust_domain": "bar.test",
      "bundle_endpoint_url": "https://bar.test/endpoint",
      "https_spiffe": {
        "endpoint_spiffe_id": "spiffe://bar.test/id"
      },
      "trust_domain_bundle": {
        "trust_domain": "bar.test",
        "x509_authorities": [],
        "jwt_authorities": [],
        "wit_authorities": [],
        "refresh_hint": "0",
        "sequence_number": "0"
      }
    },
    {
      "trust_domain": "baz.test",
      "bundle_endpoint_url": "https://baz.test/endpoint",
      "https_spiffe": {
        "endpoint_spiffe_id": "spiffe://baz.test/id"
      }
    }
  ],
  "next_page_token": ""
}`,
		},
		{
			name:      "server fails",
			serverErr: status.Error(codes.Internal, "oh! no"),
			expectErr: "Error: error listing federation relationship: rpc error: code = Internal desc = oh! no\n",
		},
	} {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, newListCommand)
				test.server.err = tt.serverErr
				test.server.expectListReq = tt.expectListReq
				test.server.listResp = tt.listResp
				args := tt.args
				args = append(args, "-output", format)

				rc := test.client.Run(test.args(args...))
				if tt.expectErr != "" {
					require.Equal(t, 1, rc)
					require.Equal(t, tt.expectErr, test.stderr.String())
					return
				}

				require.Equal(t, 0, rc)
				requireOutputBasedOnFormat(t, format, test.stdout.String(), tt.expectOutPretty, tt.expectOutJSON)
			})
		}
	}
}
