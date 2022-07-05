package entry

import (
	"errors"
	"fmt"
	"testing"
	"time"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestUpdateHelp(t *testing.T) {
	test := setupTest(t, newUpdateCommand)
	test.client.Help()

	require.Equal(t, updateUsage, test.stderr.String())
}

func TestUpdateSynopsis(t *testing.T) {
	test := setupTest(t, newUpdateCommand)
	require.Equal(t, "Updates registration entries", test.client.Synopsis())
}

func TestUpdate(t *testing.T) {
	entry1 := &types.Entry{
		Id:       "entry-id",
		SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
		ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/parent"},
		Selectors: []*types.Selector{
			{Type: "zebra", Value: "zebra:2000"},
			{Type: "alpha", Value: "alpha:2000"},
		},
		Ttl:           60,
		FederatesWith: []string{"spiffe://domaina.test", "spiffe://domainb.test"},
		Admin:         true,
		ExpiresAt:     1552410266,
		DnsNames:      []string{"unu1000", "ung1000"},
		Downstream:    true,
	}

	entryStoreSvid := &types.Entry{
		Id:       "entry-id",
		SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
		ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/parent"},
		Selectors: []*types.Selector{
			{Type: "type", Value: "key1:value"},
			{Type: "type", Value: "key2:value"},
		},
		Ttl:           60,
		FederatesWith: []string{"spiffe://domaina.test", "spiffe://domainb.test"},
		ExpiresAt:     1552410266,
		DnsNames:      []string{"unu1000", "ung1000"},
		StoreSvid:     true,
	}
	fakeRespOKFromCmd := &entryv1.BatchUpdateEntryResponse{
		Results: []*entryv1.BatchUpdateEntryResponse_Result{
			{
				Entry: entry1,
				Status: &types.Status{
					Code:    int32(codes.OK),
					Message: "OK",
				},
			},
		},
	}

	entry2 := &types.Entry{
		Id:        "entry-id-1",
		SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/Blog"},
		ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenBlog"},
		Selectors: []*types.Selector{{Type: "unix", Value: "uid:1111"}},
		Ttl:       200,
		Admin:     true,
	}

	entry3 := &types.Entry{
		Id:        "entry-id-2",
		SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/Database"},
		ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenDatabase"},
		Selectors: []*types.Selector{{Type: "unix", Value: "uid:1111"}},
		Ttl:       200,
	}

	entry4 := &types.Entry{
		Id:       "entry-id-3",
		SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/Storesvid"},
		ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenDatabase"},
		Selectors: []*types.Selector{
			{Type: "type", Value: "key1:value"},
			{Type: "type", Value: "key2:value"},
		},
		StoreSvid: true,
		Ttl:       200,
	}

	fakeRespOKFromFile := &entryv1.BatchUpdateEntryResponse{
		Results: []*entryv1.BatchUpdateEntryResponse_Result{
			{
				Entry:  entry2,
				Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
			},
			{
				Entry:  entry3,
				Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
			},
			{
				Entry:  entry4,
				Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
			},
		},
	}

	fakeRespErr := &entryv1.BatchUpdateEntryResponse{
		Results: []*entryv1.BatchUpdateEntryResponse_Result{
			{
				Status: &types.Status{
					Code:    int32(codes.NotFound),
					Message: "failed to update entry: datastore-sql: record not found",
				},
			},
		},
	}

	for _, tt := range []struct {
		name string
		args []string

		expReq    *entryv1.BatchUpdateEntryRequest
		fakeResp  *entryv1.BatchUpdateEntryResponse
		serverErr error

		expOut string
		expErr string
	}{
		{
			name:   "Missing Entry ID",
			expErr: "Error: entry ID is required\n",
		},
		{
			name:   "Missing selectors",
			args:   []string{"-entryID", "entry-id"},
			expErr: "Error: at least one selector is required\n",
		},
		{
			name:   "Missing parent SPIFFE ID",
			args:   []string{"-entryID", "entry-id", "-selector", "unix:uid:1"},
			expErr: "Error: a parent ID is required\n",
		},
		{
			name:   "Missing SPIFFE ID",
			args:   []string{"-entryID", "entry-id", "-selector", "unix:uid:1", "-parentID", "spiffe://example.org/parent"},
			expErr: "Error: a SPIFFE ID is required\n",
		},
		{
			name:   "Wrong selectors",
			args:   []string{"-entryID", "entry-id", "-selector", "unix", "-parentID", "spiffe://example.org/parent", "-spiffeID", "spiffe://example.org/workload"},
			expErr: "Error: selector \"unix\" must be formatted as type:value\n",
		},
		{
			name:   "Negative TTL",
			args:   []string{"-entryID", "entry-id", "-selector", "unix", "-parentID", "spiffe://example.org/parent", "-spiffeID", "spiffe://example.org/workload", "-ttl", "-10"},
			expErr: "Error: a positive TTL is required\n",
		},
		{
			name: "Server error",
			args: []string{"-entryID", "entry-id", "-spiffeID", "spiffe://example.org/workload", "-parentID", "spiffe://example.org/parent", "-selector", "unix:uid:1"},
			expReq: &entryv1.BatchUpdateEntryRequest{Entries: []*types.Entry{
				{
					Id:        "entry-id",
					SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
					ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/parent"},
					Selectors: []*types.Selector{{Type: "unix", Value: "uid:1"}},
				},
			}},
			serverErr: errors.New("server-error"),
			expErr:    "Error: rpc error: code = Unknown desc = server-error\n",
		},
		{
			name: "Update succeeds using command line arguments",
			args: []string{
				"-entryID", "entry-id",
				"-spiffeID", "spiffe://example.org/workload",
				"-parentID", "spiffe://example.org/parent",
				"-selector", "zebra:zebra:2000",
				"-selector", "alpha:alpha:2000",
				"-ttl", "60",
				"-federatesWith", "spiffe://domaina.test",
				"-federatesWith", "spiffe://domainb.test",
				"-admin",
				"-entryExpiry", "1552410266",
				"-dns", "unu1000",
				"-dns", "ung1000",
				"-downstream",
			},
			expReq: &entryv1.BatchUpdateEntryRequest{
				Entries: []*types.Entry{entry1},
			},
			fakeResp: fakeRespOKFromCmd,
			expOut: fmt.Sprintf(`Entry ID         : entry-id
SPIFFE ID        : spiffe://example.org/workload
Parent ID        : spiffe://example.org/parent
Revision         : 0
Downstream       : true
TTL              : 60
Expiration time  : %s
Selector         : zebra:zebra:2000
Selector         : alpha:alpha:2000
FederatesWith    : spiffe://domaina.test
FederatesWith    : spiffe://domainb.test
DNS name         : unu1000
DNS name         : ung1000
Admin            : true

`, time.Unix(1552410266, 0).UTC()),
		},
		{
			name: "Update succeeds using command line arguments Store Svid",
			args: []string{
				"-entryID", "entry-id",
				"-spiffeID", "spiffe://example.org/workload",
				"-parentID", "spiffe://example.org/parent",
				"-selector", "type:key1:value",
				"-selector", "type:key2:value",
				"-ttl", "60",
				"-federatesWith", "spiffe://domaina.test",
				"-federatesWith", "spiffe://domainb.test",
				"-entryExpiry", "1552410266",
				"-dns", "unu1000",
				"-dns", "ung1000",
				"-storeSVID",
			},
			expReq: &entryv1.BatchUpdateEntryRequest{
				Entries: []*types.Entry{entryStoreSvid},
			},
			fakeResp: &entryv1.BatchUpdateEntryResponse{
				Results: []*entryv1.BatchUpdateEntryResponse_Result{
					{
						Entry: entryStoreSvid,
						Status: &types.Status{
							Code:    int32(codes.OK),
							Message: "OK",
						},
					},
				},
			},
			expOut: fmt.Sprintf(`Entry ID         : entry-id
SPIFFE ID        : spiffe://example.org/workload
Parent ID        : spiffe://example.org/parent
Revision         : 0
TTL              : 60
Expiration time  : %s
Selector         : type:key1:value
Selector         : type:key2:value
FederatesWith    : spiffe://domaina.test
FederatesWith    : spiffe://domainb.test
DNS name         : unu1000
DNS name         : ung1000
StoreSvid        : true

`, time.Unix(1552410266, 0).UTC()),
		},
		{
			name: "Update succeeds using data file",
			args: []string{
				"-data", "../../../../test/fixture/registration/good-for-update.json",
			},
			expReq: &entryv1.BatchUpdateEntryRequest{
				Entries: []*types.Entry{entry2, entry3, entry4},
			},
			fakeResp: fakeRespOKFromFile,
			expOut: `Entry ID         : entry-id-1
SPIFFE ID        : spiffe://example.org/Blog
Parent ID        : spiffe://example.org/spire/agent/join_token/TokenBlog
Revision         : 0
TTL              : 200
Selector         : unix:uid:1111
Admin            : true

Entry ID         : entry-id-2
SPIFFE ID        : spiffe://example.org/Database
Parent ID        : spiffe://example.org/spire/agent/join_token/TokenDatabase
Revision         : 0
TTL              : 200
Selector         : unix:uid:1111

Entry ID         : entry-id-3
SPIFFE ID        : spiffe://example.org/Storesvid
Parent ID        : spiffe://example.org/spire/agent/join_token/TokenDatabase
Revision         : 0
TTL              : 200
Selector         : type:key1:value
Selector         : type:key2:value
StoreSvid        : true

`,
		},
		{
			name: "Entry not found",
			args: []string{"-entryID", "non-existent-id", "-spiffeID", "spiffe://example.org/workload", "-parentID", "spiffe://example.org/parent", "-selector", "unix:uid:1"},
			expReq: &entryv1.BatchUpdateEntryRequest{Entries: []*types.Entry{
				{
					Id:        "non-existent-id",
					SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
					ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/parent"},
					Selectors: []*types.Selector{{Type: "unix", Value: "uid:1"}},
				},
			}},
			fakeResp: fakeRespErr,
			expErr: `Failed to update the following entry (code: NotFound, msg: "failed to update entry: datastore-sql: record not found"):
Entry ID         : non-existent-id
SPIFFE ID        : spiffe://example.org/workload
Parent ID        : spiffe://example.org/parent
Revision         : 0
TTL              : default
Selector         : unix:uid:1

Error: failed to update one or more entries
`,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, newUpdateCommand)
			test.server.err = tt.serverErr
			test.server.expBatchUpdateEntryReq = tt.expReq
			test.server.batchUpdateEntryResp = tt.fakeResp

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
