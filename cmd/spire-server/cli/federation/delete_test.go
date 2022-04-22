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

func TestDeleteHelp(t *testing.T) {
	test := setupTest(t, newDeleteCommand)
	test.client.Help()

	require.Equal(t, `Usage of federation delete:
  -id string
    	SPIFFE ID of the trust domain`+common.AddrUsage, test.stderr.String())
}

func TestDeleteSynopsis(t *testing.T) {
	test := setupTest(t, newDeleteCommand)
	require.Equal(t, "Deletes a dynamic federation relationship", test.client.Synopsis())
}

func TestDelete(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string

		expectReq  *trustdomainv1.BatchDeleteFederationRelationshipRequest
		deleteResp *trustdomainv1.BatchDeleteFederationRelationshipResponse
		serverErr  error

		expectOut string
		expectErr string
	}{
		{
			name: "Success",
			args: []string{"-id", "spiffe://example.org"},
			expectReq: &trustdomainv1.BatchDeleteFederationRelationshipRequest{
				TrustDomains: []string{"spiffe://example.org"},
			},
			deleteResp: &trustdomainv1.BatchDeleteFederationRelationshipResponse{
				Results: []*trustdomainv1.BatchDeleteFederationRelationshipResponse_Result{
					{
						Status:      &types.Status{Code: int32(codes.OK)},
						TrustDomain: "example.org",
					},
				},
			},
			expectOut: "federation relationship deleted.\n",
		},
		{
			name:      "Empty ID",
			expectErr: "Error: id is required\n",
		},
		{
			name:      "Server client fails",
			args:      []string{"-id", "spiffe://example.org"},
			serverErr: status.Error(codes.Internal, "oh! no"),
			expectErr: `Error: failed to delete federation relationship: rpc error: code = Internal desc = oh! no
`,
		},
		{
			name: "Delete fails",
			args: []string{"-id", "spiffe://example.org"},
			expectReq: &trustdomainv1.BatchDeleteFederationRelationshipRequest{
				TrustDomains: []string{"spiffe://example.org"},
			},
			deleteResp: &trustdomainv1.BatchDeleteFederationRelationshipResponse{
				Results: []*trustdomainv1.BatchDeleteFederationRelationshipResponse_Result{
					{
						Status: &types.Status{
							Code:    int32(codes.Internal),
							Message: "oh! no",
						},
						TrustDomain: "example.org",
					},
				},
			},
			expectErr: `Error: failed to delete federation relationship "example.org": oh! no
`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, newDeleteCommand)
			test.server.err = tt.serverErr
			test.server.expectDeleteReq = tt.expectReq
			test.server.deleteResp = tt.deleteResp

			rc := test.client.Run(test.args(tt.args...))
			if tt.expectErr != "" {
				require.Equal(t, 1, rc)
				require.Equal(t, tt.expectErr, test.stderr.String())
				return
			}

			require.Equal(t, 0, rc)
			require.Equal(t, tt.expectOut, test.stdout.String())
			require.Empty(t, test.stderr.String())
		})
	}
}
