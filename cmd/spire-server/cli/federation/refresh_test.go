package federation

import (
	"testing"

	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire/cmd/spire-server/cli/common"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestRefreshHelp(t *testing.T) {
	test := setupTest(t, newRefreshCommand)
	test.client.Help()

	require.Equal(t, `Usage of federation refresh:
  -id string
    	SPIFFE ID of the trust domain`+common.AddrUsage, test.stderr.String())
}

func TestRefreshSynopsis(t *testing.T) {
	test := setupTest(t, newRefreshCommand)
	require.Equal(t, "Refreshes the bundle from the specified federated trust domain", test.client.Synopsis())
}

func TestRefresh(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string

		expectReq   *trustdomainv1.RefreshBundleRequest
		refreshResp *emptypb.Empty
		serverErr   error

		expectOut string
		expectErr string
	}{
		{
			name: "Success",
			args: []string{"-id", "spiffe://example.org"},
			expectReq: &trustdomainv1.RefreshBundleRequest{
				TrustDomain: "spiffe://example.org",
			},
			expectOut:   "Bundle refreshed\n",
			refreshResp: &emptypb.Empty{},
		},
		{
			name:      "Empty ID",
			expectErr: "Error: id is required\n",
		},
		{
			name:      "Server client fails",
			args:      []string{"-id", "spiffe://example.org"},
			serverErr: status.Error(codes.Internal, "oh! no"),
			expectErr: `Error: failed to refresh bundle: rpc error: code = Internal desc = oh! no
`,
		},
		{
			name:      "Bundle not found",
			args:      []string{"-id", "spiffe://example.org"},
			serverErr: status.Error(codes.NotFound, "not found"),
			expectErr: `Error: there is no federation relationship with trust domain "spiffe://example.org"
`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, newRefreshCommand)
			test.server.err = tt.serverErr
			test.server.expectRefreshReq = tt.expectReq
			test.server.refreshResp = tt.refreshResp

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
