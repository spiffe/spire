package entry

import (
	"fmt"
	"testing"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCountHelp(t *testing.T) {
	test := setupTest(t, NewCountCommandWithEnv)
	test.client.Help()

	require.Equal(t, countUsage, test.stderr.String())
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
		expOutPretty  string
		expOutJSON    string
		expErr        string
	}{
		{
			name:          "4 entries",
			fakeCountResp: fakeResp4,
			expOutPretty:  "4 registration entries\n",
			expOutJSON:    `{"count":4}`,
		},
		{
			name:          "2 entries",
			fakeCountResp: fakeResp2,
			expOutPretty:  "2 registration entries\n",
			expOutJSON:    `{"count":2}`,
		},
		{
			name:          "1 entry",
			fakeCountResp: fakeResp1,
			expOutPretty:  "1 registration entry\n",
			expOutJSON:    `{"count":1}`,
		},
		{
			name:          "0 entries",
			fakeCountResp: fakeResp0,
			expOutPretty:  "0 registration entries\n",
			expOutJSON:    `{"count":0}`,
		},
		{
			name:      "Server error",
			serverErr: status.Error(codes.Internal, "internal server error"),
			expErr:    "Error: rpc error: code = Internal desc = internal server error\n",
		},
	} {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, NewCountCommandWithEnv)
				test.server.err = tt.serverErr
				test.server.countEntriesResp = tt.fakeCountResp

				rc := test.client.Run(test.args(tt.args...))
				if tt.expErr != "" {
					require.Equal(t, 1, rc)
					require.Equal(t, tt.expErr, test.stderr.String())
					return
				}
				requireOutputBasedOnFormat(t, test.stdout.String(), format, tt.expOutPretty, tt.expOutJSON)
				require.Equal(t, 0, rc)
			})
		}
	}
}
