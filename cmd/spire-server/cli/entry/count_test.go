package entry

import (
	"testing"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/cmd/spire-server/cli/common"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCountHelp(t *testing.T) {
	test := setupTest(t, NewCountCommandWithEnv)
	test.client.Help()

	require.Equal(t, `Usage of entry count:`+common.AddrUsage, test.stderr.String())
}

func TestCountSynopsis(t *testing.T) {
	test := setupTest(t, NewCountCommandWithEnv)
	require.Equal(t, "Count registration entries", test.client.Synopsis())
}

func TestCount(t *testing.T) {
	fakeResp4 := &entryv1.CountEntriesResponse{Count: 4}
	fakeResp2 := &entryv1.CountEntriesResponse{Count: 2}
	fakeResp1 := &entryv1.CountEntriesResponse{Count: 1}
	fakeResp0 := &entryv1.CountEntriesResponse{Count: 0}

	for _, tt := range []struct {
		name          string
		args          []string
		fakeCountResp *entryv1.CountEntriesResponse
		serverErr     error
		expOut        string
		expErr        string
	}{
		{
			name:          "4 entries",
			fakeCountResp: fakeResp4,
			expOut:        "4 registration entries\n",
		},
		{
			name:          "2 entries",
			fakeCountResp: fakeResp2,
			expOut:        "2 registration entries\n",
		},
		{
			name:          "1 entry",
			fakeCountResp: fakeResp1,
			expOut:        "1 registration entry\n",
		},
		{
			name:          "0 entries",
			fakeCountResp: fakeResp0,
			expOut:        "0 registration entries\n",
		},
		{
			name:      "Server error",
			serverErr: status.Error(codes.Internal, "internal server error"),
			expErr:    "Error: rpc error: code = Internal desc = internal server error\n",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, NewCountCommandWithEnv)
			test.server.err = tt.serverErr
			test.server.countEntriesResp = tt.fakeCountResp

			rc := test.client.Run(test.args(tt.args...))
			if tt.expErr != "" {
				require.Equal(t, 1, rc)
				require.Equal(t, tt.expErr, test.stderr.String())
				return
			}

			require.Equal(t, 0, rc)
			require.Equal(t, tt.expOut, test.stdout.String())
		})
	}
}
