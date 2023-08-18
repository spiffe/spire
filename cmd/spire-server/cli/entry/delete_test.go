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
			name:     "Entry not found",
			args:     []string{"-entryID", "entry-id"},
			expReq:   &entryv1.BatchDeleteEntryRequest{Ids: []string{"entry-id"}},
			fakeResp: fakeRespErr,
			expErrPretty: "Failed to delete entry with ID entry-id (code: NotFound, msg: \"entry not found\")" +
				"\nError: failed to delete one or more entries\n",
			expOutJSON: `{"results":[{"status":{"code":5,"message":"entry not found"},"id":"entry-id"}]}`,
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
			name:   "Delete succeeded",
			args:   []string{"-entryID", "entry-0"},
			expReq: &entryv1.BatchDeleteEntryRequest{Ids: []string{"entry-0"}},
			fakeResp: &entryv1.BatchDeleteEntryResponse{
				Results: []*entryv1.BatchDeleteEntryResponse_Result{
					{
						Id: "entry-0",
						Status: &types.Status{
							Code:    int32(codes.OK),
							Message: "OK",
						},
					},
				},
			},
			expOutPretty: "Deleted entry with ID: entry-0\n",
			expOutJSON:   `{"results":[{"status":{"code":0,"message":"OK"},"id":"entry-0"}]}`,
		},
		{
			name:   "Delete succeeded using data file",
			args:   []string{"-file", "../../../../test/fixture/registration/good-for-delete.json"},
			expReq: &entryv1.BatchDeleteEntryRequest{Ids: []string{"entry-0", "entry-1"}},
			fakeResp: &entryv1.BatchDeleteEntryResponse{
				Results: []*entryv1.BatchDeleteEntryResponse_Result{
					{
						Id: "entry-0",
						Status: &types.Status{
							Code:    int32(codes.OK),
							Message: "OK",
						},
					},
					{
						Id: "entry-1",
						Status: &types.Status{
							Code:    int32(codes.OK),
							Message: "OK",
						},
					},
				},
			},
			expOutPretty: "Deleted entry with ID: entry-0\nDeleted entry with ID: entry-1\n",
			expOutJSON:   `{"results":[{"status":{"code":0,"message":"OK"},"id":"entry-0"},{"status":{"code":0,"message":"OK"},"id":"entry-1"}]}`,
		},
		{
			name:   "Delete partially succeeded",
			args:   []string{"-file", "../../../../test/fixture/registration/partially-good-for-delete.json"},
			expReq: &entryv1.BatchDeleteEntryRequest{Ids: []string{"entry-0", "entry-1", "entry-2", "entry-3"}},
			fakeResp: &entryv1.BatchDeleteEntryResponse{
				Results: []*entryv1.BatchDeleteEntryResponse_Result{
					{
						Id: "entry-0",
						Status: &types.Status{
							Code:    int32(codes.NotFound),
							Message: "entry not found",
						},
					},
					{
						Id: "entry-1",
						Status: &types.Status{
							Code:    int32(codes.OK),
							Message: "OK",
						},
					},
					{
						Id: "entry-2",
						Status: &types.Status{
							Code:    int32(codes.NotFound),
							Message: "entry not found",
						},
					},
					{
						Id: "entry-3",
						Status: &types.Status{
							Code:    int32(codes.OK),
							Message: "OK",
						},
					},
				},
			},
			expOutPretty: "Deleted entry with ID: entry-1\nDeleted entry with ID: entry-3\n",
			expErrPretty: "Failed to delete entry with ID entry-0 (code: NotFound, msg: \"entry not found\")\n" +
				"Failed to delete entry with ID entry-2 (code: NotFound, msg: \"entry not found\")\n" +
				"Error: failed to delete one or more entries\n",
			expOutJSON: `{"results":[` +
				`{"status":{"code":5,"message":"entry not found"},"id":"entry-0"},` +
				`{"status":{"code":0,"message":"OK"},"id":"entry-1"},` +
				`{"status":{"code":5,"message":"entry not found"},"id":"entry-2"},` +
				`{"status":{"code":0,"message":"OK"},"id":"entry-3"}]}`,
		},
		{
			name:   "Delete failed",
			args:   []string{"-entryID", "entry-0"},
			expReq: &entryv1.BatchDeleteEntryRequest{Ids: []string{"entry-0"}},
			fakeResp: &entryv1.BatchDeleteEntryResponse{
				Results: []*entryv1.BatchDeleteEntryResponse_Result{
					{
						Id: "entry-0",
						Status: &types.Status{
							Code:    int32(codes.NotFound),
							Message: "entry not found",
						},
					},
				},
			},
			expErrPretty: "Failed to delete entry with ID entry-0 (code: NotFound, msg: \"entry not found\")\n" +
				"Error: failed to delete one or more entries\n",
			expOutJSON: `{"results":[` +
				`{"status":{"code":5,"message":"entry not found"},"id":"entry-0"}]}`,
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
