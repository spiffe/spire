package entry

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/spiffe/spire/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestUpdateHelp(t *testing.T) {
	test := setupTest(t, newUpdateCommand)
	test.client.Help()

	require.Equal(t, `Usage of entry update:
  -admin
    	If true, the SPIFFE ID in this entry will be granted access to the Registration API
  -data string
    	Path to a file containing registration JSON (optional). If set to '-', read the JSON from stdin.
  -dns value
    	A DNS name that will be included in SVIDs issued based on this entry, where appropriate. Can be used more than once
  -downstream
    	A boolean value that, when set, indicates that the entry describes a downstream SPIRE server
  -entryExpiry int
    	An expiry, from epoch in seconds, for the resulting registration entry to be pruned
  -entryID string
    	The Registration Entry ID of the record to update
  -federatesWith value
    	SPIFFE ID of a trust domain to federate with. Can be used more than once
  -parentID string
    	The SPIFFE ID of this record's parent
  -registrationUDSPath string
    	Registration API UDS path (default "/tmp/spire-registration.sock")
  -selector value
    	A colon-delimited type:value selector. Can be used more than once
  -spiffeID string
    	The SPIFFE ID that this record represents
  -ttl int
    	The lifetime, in seconds, for SVIDs issued based on this registration entry
`, test.stderr.String())
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

	fakeRespOKFromCmd := &entry.BatchUpdateEntryResponse{
		Results: []*entry.BatchUpdateEntryResponse_Result{
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

	fakeRespOKFromFile := &entry.BatchUpdateEntryResponse{
		Results: []*entry.BatchUpdateEntryResponse_Result{
			{
				Entry:  entry2,
				Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
			},
			{
				Entry:  entry3,
				Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
			},
		},
	}

	fakeRespErr := &entry.BatchUpdateEntryResponse{
		Results: []*entry.BatchUpdateEntryResponse_Result{
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

		expReq    *entry.BatchUpdateEntryRequest
		fakeResp  *entry.BatchUpdateEntryResponse
		serverErr error

		expOut string
		expErr string
	}{
		{
			name:   "Missing Entry ID",
			expErr: "entry ID is required\n",
		},
		{
			name:   "Missing selectors",
			args:   []string{"-entryID", "entry-id"},
			expErr: "at least one selector is required\n",
		},
		{
			name:   "Missing parent SPIFFE ID",
			args:   []string{"-entryID", "entry-id", "-selector", "unix:uid:1"},
			expErr: "a parent ID is required\n",
		},
		{
			name:   "Missing SPIFFE ID",
			args:   []string{"-entryID", "entry-id", "-selector", "unix:uid:1", "-parentID", "spiffe://example.org/parent"},
			expErr: "a SPIFFE ID is required\n",
		},
		{
			name:   "Wrong SPIFFE ID",
			args:   []string{"-entryID", "entry-id", "-selector", "unix:uid:1", "-parentID", "spiffe://example.org/parent", "-spiffeID", "invalid-id"},
			expErr: "\"invalid-id\" is not a valid SPIFFE ID: invalid scheme\n",
		},
		{
			name:   "Wrong parent SPIFFE ID",
			args:   []string{"-entryID", "entry-id", "-selector", "unix:uid:1", "-parentID", "invalid-id", "-spiffeID", "spiffe://example.org/workload"},
			expErr: "\"invalid-id\" is not a valid SPIFFE ID: invalid scheme\n",
		},
		{
			name:   "Wrong selectors",
			args:   []string{"-entryID", "entry-id", "-selector", "unix", "-parentID", "spiffe://example.org/parent", "-spiffeID", "spiffe://example.org/workload"},
			expErr: "selector \"unix\" must be formatted as type:value\n",
		},
		{
			name:   "Negative TTL",
			args:   []string{"-entryID", "entry-id", "-selector", "unix", "-parentID", "spiffe://example.org/parent", "-spiffeID", "spiffe://example.org/workload", "-ttl", "-10"},
			expErr: "a positive TTL is required\n",
		},
		{
			name:   "Wrong federated trust domain",
			args:   []string{"-entryID", "entry-id", "-selector", "unix", "-spiffeID", "spiffe://example.org/workload", "-parentID", "spiffe://example.org/parent", "-federatesWith", "invalid-id"},
			expErr: "\"invalid-id\" is not a valid SPIFFE ID: invalid scheme\n",
		},
		{
			name: "Server error",
			args: []string{"-entryID", "entry-id", "-spiffeID", "spiffe://example.org/workload", "-parentID", "spiffe://example.org/parent", "-selector", "unix:uid:1"},
			expReq: &entry.BatchUpdateEntryRequest{Entries: []*types.Entry{
				{
					Id:        "entry-id",
					SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
					ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/parent"},
					Selectors: []*types.Selector{{Type: "unix", Value: "uid:1"}},
				},
			}},
			serverErr: errors.New("server-error"),
			expErr:    "rpc error: code = Unknown desc = server-error\n",
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
				"-federatesWith", "spiffe://domainA.test",
				"-federatesWith", "spiffe://domainB.test",
				"-admin",
				"-entryExpiry", "1552410266",
				"-dns", "unu1000",
				"-dns", "ung1000",
				"-downstream",
			},
			expReq: &entry.BatchUpdateEntryRequest{
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
			name: "Update succeeds using data file",
			args: []string{
				"-data", "../../../../test/fixture/registration/good-for-update.json",
			},
			expReq: &entry.BatchUpdateEntryRequest{
				Entries: []*types.Entry{entry2, entry3},
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

`,
		},
		{
			name: "Entry not found",
			args: []string{"-entryID", "non-existent-id", "-spiffeID", "spiffe://example.org/workload", "-parentID", "spiffe://example.org/parent", "-selector", "unix:uid:1"},
			expReq: &entry.BatchUpdateEntryRequest{Entries: []*types.Entry{
				{
					Id:        "non-existent-id",
					SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
					ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/parent"},
					Selectors: []*types.Selector{{Type: "unix", Value: "uid:1"}},
				},
			}},
			fakeResp: fakeRespErr,
			expOut: `FAILED to update the following entry:
Entry ID         : non-existent-id
SPIFFE ID        : spiffe://example.org/workload
Parent ID        : spiffe://example.org/parent
Revision         : 0
TTL              : default
Selector         : unix:uid:1

failed to update entry: datastore-sql: record not found
`,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, newUpdateCommand)
			test.server.err = tt.serverErr
			test.server.expBatchUpdateEntryReq = tt.expReq
			test.server.batchUpdateEntryResp = tt.fakeResp

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
