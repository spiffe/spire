package federation

import (
	"fmt"
	"testing"

	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestRefreshHelp(t *testing.T) {
	test := setupTest(t, newRefreshCommand)
	test.client.Help()

	require.Equal(t, refreshUsage, test.stderr.String())
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

		expectOutPretty string
		expectOutJSON   string
		expectErr       string
	}{
		{
			name: "Success",
			args: []string{"-id", "spiffe://example.org"},
			expectReq: &trustdomainv1.RefreshBundleRequest{
				TrustDomain: "spiffe://example.org",
			},
			expectOutPretty: "Bundle refreshed\n",
			expectOutJSON:   `{"code":0,"message":"OK"}`,
			refreshResp:     &emptypb.Empty{},
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
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, newRefreshCommand)
				test.server.err = tt.serverErr
				test.server.expectRefreshReq = tt.expectReq
				test.server.refreshResp = tt.refreshResp
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
				require.Empty(t, test.stderr.String())
			})
		}
	}
}
