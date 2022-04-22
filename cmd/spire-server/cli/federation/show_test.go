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

func TestShowHelp(t *testing.T) {
	test := setupTest(t, newShowCommand)
	test.client.Help()

	require.Equal(t, `Usage of federation show:`+common.AddrUsage+
		`  -trustDomain string
    	The trust domain name of the federation relationship to show
`, test.stderr.String())
}

func TestShowSynopsis(t *testing.T) {
	test := setupTest(t, newShowCommand)
	require.Equal(t, "Shows a dynamic federation relationship", test.client.Synopsis())
}

func TestShow(t *testing.T) {
	fr1 := &types.FederationRelationship{
		TrustDomain:           "example-1.test",
		BundleEndpointUrl:     "https://bundle-endpoint-1.test/endpoint",
		BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
	}

	fr2 := &types.FederationRelationship{
		TrustDomain:       "example-2.test",
		BundleEndpointUrl: "https://bundle-endpoint-2.test/endpoint",
		BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
			HttpsSpiffe: &types.HTTPSSPIFFEProfile{
				EndpointSpiffeId: "spiffe://endpoint.test/id",
			},
		},
		TrustDomainBundle: &types.Bundle{TrustDomain: "endpoint.test"},
	}

	for _, tt := range []struct {
		name string
		args []string

		req       *trustdomainv1.GetFederationRelationshipRequest
		resp      *types.FederationRelationship
		serverErr error

		expectedStdout string
		expectedStderr string
	}{
		{
			name: "succeeds https_web",
			req:  &trustdomainv1.GetFederationRelationshipRequest{},
			resp: fr1,
			args: []string{"-trustDomain", "example-1.test"},
			expectedStdout: `Found a federation relationship with trust domain example-1.test:

Trust domain              : example-1.test
Bundle endpoint URL       : https://bundle-endpoint-1.test/endpoint
Bundle endpoint profile   : https_web
`,
		},
		{
			name: "succeeds https_spiffe",
			req:  &trustdomainv1.GetFederationRelationshipRequest{},
			resp: fr2,
			args: []string{"-trustDomain", "example-2.test"},
			expectedStdout: `Found a federation relationship with trust domain example-2.test:

Trust domain              : example-2.test
Bundle endpoint URL       : https://bundle-endpoint-2.test/endpoint
Bundle endpoint profile   : https_spiffe
Endpoint SPIFFE ID        : spiffe://endpoint.test/id
`,
		},
		{
			name:           "server fails",
			args:           []string{"-trustDomain", "example-1.test"},
			serverErr:      status.Error(codes.Internal, "oh! no"),
			expectedStderr: "Error: error showing federation relationship: rpc error: code = Internal desc = oh! no\n",
		},
		{
			name: "no trust domain specified",
			req: &trustdomainv1.GetFederationRelationshipRequest{
				TrustDomain: "does-not-exist.org",
			},
			resp:           nil,
			expectedStderr: "Error: a trust domain name is required\n",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, newShowCommand)
			test.server.err = tt.serverErr
			test.server.expectShowReq = tt.req
			test.server.showResp = tt.resp

			rc := test.client.Run(test.args(tt.args...))
			if tt.expectedStderr != "" {
				require.Equal(t, 1, rc)
				require.Equal(t, tt.expectedStderr, test.stderr.String())
				return
			}

			require.Equal(t, 0, rc)
			require.Equal(t, tt.expectedStdout, test.stdout.String())
		})
	}
}
