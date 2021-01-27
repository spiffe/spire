package entry

import (
	"errors"
	"testing"

	"github.com/spiffe/spire/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestDeleteHelp(t *testing.T) {
	test := setupTest(t, newDeleteCommand)
	test.client.Help()

	require.Equal(t, `Usage of entry delete:
  -entryID string
    	The Registration Entry ID of the record to delete
  -registrationUDSPath string
    	Path to the SPIRE Server API socket (deprecated; use -socketPath)
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`, test.stderr.String())
}

func TestDeleteSynopsis(t *testing.T) {
	test := setupTest(t, newDeleteCommand)
	require.Equal(t, "Deletes registration entries", test.client.Synopsis())
}

func TestDelete(t *testing.T) {
	fakeRespOK := &entry.BatchDeleteEntryResponse{
		Results: []*entry.BatchDeleteEntryResponse_Result{
			{
				Id: "entry-id",
				Status: &types.Status{
					Code:    int32(codes.OK),
					Message: "OK",
				},
			},
		},
	}

	fakeRespErr := &entry.BatchDeleteEntryResponse{
		Results: []*entry.BatchDeleteEntryResponse_Result{
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

		expReq    *entry.BatchDeleteEntryRequest
		fakeResp  *entry.BatchDeleteEntryResponse
		serverErr error

		expOut string
		expErr string
	}{
		{
			name:   "Empty entry ID",
			expErr: "Error: an entry ID is required\n",
		},
		{
			name:     "Entry not found",
			args:     []string{"-entryID", "entry-id"},
			expReq:   &entry.BatchDeleteEntryRequest{Ids: []string{"entry-id"}},
			fakeResp: fakeRespErr,
			expErr:   "Error: failed to delete entry: entry not found\n",
		},
		{
			name:      "Server error",
			args:      []string{"-entryID", "entry-id"},
			expReq:    &entry.BatchDeleteEntryRequest{Ids: []string{"entry-id"}},
			serverErr: errors.New("server-error"),
			expErr:    "Error: rpc error: code = Unknown desc = server-error\n",
		},
		{
			name:     "Delete succeeds",
			args:     []string{"-entryID", "entry-id"},
			expReq:   &entry.BatchDeleteEntryRequest{Ids: []string{"entry-id"}},
			fakeResp: fakeRespOK,
			expOut:   "Deleted entry with ID: entry-id\n",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, newDeleteCommand)
			test.server.err = tt.serverErr
			test.server.expBatchDeleteEntryReq = tt.expReq
			test.server.batchDeleteEntryResp = tt.fakeResp

			args := append(test.args, tt.args...)
			rc := test.client.Run(args)
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
