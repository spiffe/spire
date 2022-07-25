package federation

import (
	"testing"

	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/cli/common"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestListHelp(t *testing.T) {
	test := setupTest(t, newListCommand)
	test.client.Help()

	require.Equal(t, `Usage of federation list:`+common.AddrUsage, test.stderr.String())
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

		expectOut string
		expectErr string
	}{
		{
			name:          "no federations",
			expectListReq: &trustdomainv1.ListFederationRelationshipsRequest{},
			listResp:      &trustdomainv1.ListFederationRelationshipsResponse{},
			expectOut:     "Found 0 federation relationships\n",
		},
		{
			name:          "single federation",
			expectListReq: &trustdomainv1.ListFederationRelationshipsRequest{},
			listResp: &trustdomainv1.ListFederationRelationshipsResponse{
				FederationRelationships: []*types.FederationRelationship{federation1},
			},
			expectOut: `Found 1 federation relationship

Trust domain              : foh.test
Bundle endpoint URL       : https://foo.test/endpoint
Bundle endpoint profile   : https_web
`,
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
			expectOut: `Found 3 federation relationships

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
		},
		{
			name:      "server fails",
			serverErr: status.Error(codes.Internal, "oh! no"),
			expectErr: "Error: error listing federation relationship: rpc error: code = Internal desc = oh! no\n",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, newListCommand)
			test.server.err = tt.serverErr
			test.server.expectListReq = tt.expectListReq
			test.server.listResp = tt.listResp

			rc := test.client.Run(test.args(tt.args...))
			if tt.expectErr != "" {
				require.Equal(t, 1, rc)
				require.Equal(t, tt.expectErr, test.stderr.String())
				return
			}

			require.Equal(t, 0, rc)
			require.Equal(t, tt.expectOut, test.stdout.String())
		})
	}
}
