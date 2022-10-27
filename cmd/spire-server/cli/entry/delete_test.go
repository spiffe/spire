package entry

import (
	"errors"
	"fmt"
	"testing"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestDeleteHelp(t *testing.T) {
	test := setupTest(t, newDeleteCommand)
	test.client.Help()

	require.Equal(t, deleteUsage, test.stderr.String())
}

func TestDeleteSynopsis(t *testing.T) {
	test := setupTest(t, newDeleteCommand)
	require.Equal(t, "Deletes registration entries", test.client.Synopsis())
}

func TestDelete(t *testing.T) {
	fakeRespOK := &entryv1.BatchDeleteEntryResponse{
		Results: []*entryv1.BatchDeleteEntryResponse_Result{
			{
				Id: "entry-id",
				Status: &types.Status{
					Code:    int32(codes.OK),
					Message: "OK",
				},
			},
		},
	}

	fakeRespErr := &entryv1.BatchDeleteEntryResponse{
		Results: []*entryv1.BatchDeleteEntryResponse_Result{
			{
				Id: "entry-id",
				Status: &types.Status{
					Code:    int32(codes.NotFound),
					Message: "entry not found",
				},
			},
		},
	}

	for _, tt := range []struct {
		name string
		args []string

		expReq    *entryv1.BatchDeleteEntryRequest
		fakeResp  *entryv1.BatchDeleteEntryResponse
		serverErr error

		expOutPretty string
		expOutJSON   string
		expErrPretty string
		expErrJSON   string
	}{
		{
			name:         "Empty entry ID",
			expErrPretty: "Error: an entry ID is required\n",
			expErrJSON:   "Error: an entry ID is required\n",
		},
		{
			name:         "Entry not found",
			args:         []string{"-entryID", "entry-id"},
			expReq:       &entryv1.BatchDeleteEntryRequest{Ids: []string{"entry-id"}},
			fakeResp:     fakeRespErr,
			expErrPretty: "Error: failed to delete entry: entry not found\n",
			expOutJSON:   `{"results":[{"status":{"code":5,"message":"entry not found"},"id":"entry-id"}]}`,
		},
		{
			name:         "Server error",
			args:         []string{"-entryID", "entry-id"},
			expReq:       &entryv1.BatchDeleteEntryRequest{Ids: []string{"entry-id"}},
			serverErr:    errors.New("server-error"),
			expErrPretty: "Error: rpc error: code = Unknown desc = server-error\n",
			expErrJSON:   "Error: rpc error: code = Unknown desc = server-error\n",
		},
		{
			name:         "Delete succeeds",
			args:         []string{"-entryID", "entry-id"},
			expReq:       &entryv1.BatchDeleteEntryRequest{Ids: []string{"entry-id"}},
			fakeResp:     fakeRespOK,
			expOutPretty: "Deleted entry with ID: entry-id\n",
			expOutJSON:   `{"results":[{"status":{"code":0,"message":"OK"},"id":"entry-id"}]}`,
		},
	} {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, newDeleteCommand)
				test.server.err = tt.serverErr
				test.server.expBatchDeleteEntryReq = tt.expReq
				test.server.batchDeleteEntryResp = tt.fakeResp
				args := tt.args
				args = append(args, "-output", format)

				rc := test.client.Run(test.args(args...))

				if tt.expErrJSON != "" && format == "json" {
					require.Equal(t, 1, rc)
					require.Equal(t, tt.expErrJSON, test.stderr.String())
					return
				}
				if tt.expErrPretty != "" && format == "pretty" {
					require.Equal(t, 1, rc)
					require.Equal(t, tt.expErrPretty, test.stderr.String())
					return
				}
				requireOutputBasedOnFormat(t, format, test.stdout.String(), tt.expOutPretty, tt.expOutJSON)
				require.Equal(t, 0, rc)
			})
		}
	}
}
