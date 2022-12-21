package federation

import (
	"fmt"
	"testing"

	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDeleteHelp(t *testing.T) {
	test := setupTest(t, newDeleteCommand)
	test.client.Help()

	require.Equal(t, deleteUsage, test.stderr.String())
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

		expectOutPretty string
		expectOutJSON   string
		expectErrPretty string
		expectErrJSON   string
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
						Status:      api.OK(),
						TrustDomain: "example.org",
					},
				},
			},
			expectOutPretty: "federation relationship deleted.\n",
			expectOutJSON:   `{"results":[{"status":{"code":0,"message":"OK"},"trust_domain":"example.org"}]}`,
		},
		{
			name:            "Empty ID",
			expectErrPretty: "Error: id is required\n",
			expectErrJSON:   "Error: id is required\n",
		},
		{
			name:      "Server client fails",
			args:      []string{"-id", "spiffe://example.org"},
			serverErr: status.Error(codes.Internal, "oh! no"),
			expectErrPretty: `Error: failed to delete federation relationship: rpc error: code = Internal desc = oh! no
`,
			expectErrJSON: `Error: failed to delete federation relationship: rpc error: code = Internal desc = oh! no
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
			expectErrPretty: `Error: failed to delete federation relationship "example.org": oh! no
`,
			expectOutJSON: `{"results":[{"status":{"code":13,"message":"oh! no"},"trust_domain":"example.org"}]}`,
		},
	} {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, newDeleteCommand)
				test.server.err = tt.serverErr
				test.server.expectDeleteReq = tt.expectReq
				test.server.deleteResp = tt.deleteResp
				args := tt.args
				args = append(args, "-output", format)

				rc := test.client.Run(test.args(args...))

				if tt.expectErrPretty != "" && format == "pretty" {
					require.Equal(t, 1, rc)
					require.Equal(t, tt.expectErrPretty, test.stderr.String())
					return
				}
				if tt.expectErrJSON != "" && format == "json" {
					require.Equal(t, 1, rc)
					require.Equal(t, tt.expectErrJSON, test.stderr.String())
					return
				}

				require.Equal(t, 0, rc)
				requireOutputBasedOnFormat(t, format, test.stdout.String(), tt.expectOutPretty, tt.expectOutJSON)
				require.Empty(t, test.stderr.String())
			})
		}
	}
}
