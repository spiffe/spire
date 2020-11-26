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

func TestCreateHelp(t *testing.T) {
	test := setupTest(t, newCreateCommand)
	test.client.Help()

	require.Equal(t, `Usage of entry create:
  -admin
    	If set, the SPIFFE ID in this entry will be granted access to the Registration API
  -data string
    	Path to a file containing registration JSON (optional). If set to '-', read the JSON from stdin.
  -dns value
    	A DNS name that will be included in SVIDs issued based on this entry, where appropriate. Can be used more than once
  -downstream
    	A boolean value that, when set, indicates that the entry describes a downstream SPIRE server
  -entryExpiry int
    	An expiry, from epoch in seconds, for the resulting registration entry to be pruned
  -federatesWith value
    	SPIFFE ID of a trust domain to federate with. Can be used more than once
  -node
    	If set, this entry will be applied to matching nodes rather than workloads
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

func TestCreateSynopsis(t *testing.T) {
	test := setupTest(t, newCreateCommand)
	require.Equal(t, "Creates registration entries", test.client.Synopsis())
}

func TestCreate(t *testing.T) {
	fakeRespOKFromCmd := &entry.BatchCreateEntryResponse{
		Results: []*entry.BatchCreateEntryResponse_Result{
			{
				Entry: &types.Entry{
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
				},
				Status: &types.Status{
					Code:    int32(codes.OK),
					Message: "OK",
				},
			},
		},
	}

	fakeRespOKFromFile := &entry.BatchCreateEntryResponse{
		Results: []*entry.BatchCreateEntryResponse_Result{
			{
				Entry: &types.Entry{
					Id:        "entry-id-1",
					SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/Blog"},
					ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenBlog"},
					Selectors: []*types.Selector{{Type: "unix", Value: "uid:1111"}},
					Ttl:       200,
					Admin:     true,
				},
				Status: &types.Status{
					Code:    int32(codes.OK),
					Message: "OK",
				},
			},
			{
				Entry: &types.Entry{
					Id:        "entry-id-2",
					SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/Database"},
					ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenDatabase"},
					Selectors: []*types.Selector{{Type: "unix", Value: "uid:1111"}},
					Ttl:       200,
				},
				Status: &types.Status{
					Code:    int32(codes.OK),
					Message: "OK",
				},
			},
		},
	}

	fakeRespErr := &entry.BatchCreateEntryResponse{
		Results: []*entry.BatchCreateEntryResponse_Result{
			{
				Status: &types.Status{
					Code:    int32(codes.AlreadyExists),
					Message: "similar entry already exists",
				},
			},
		},
	}

	for _, tt := range []struct {
		name string
		args []string

		expReq    *entry.BatchCreateEntryRequest
		fakeResp  *entry.BatchCreateEntryResponse
		serverErr error

		expOut string
		expErr string
	}{
		{
			name:   "Missing selectors",
			expErr: "at least one selector is required\n",
		},
		{
			name:   "Missing parent SPIFFE ID",
			args:   []string{"-selector", "unix:uid:1"},
			expErr: "a parent ID is required if the node flag is not set\n",
		},
		{
			name:   "Missing SPIFFE ID",
			args:   []string{"-selector", "unix:uid:1", "-parentID", "spiffe://example.org/parent"},
			expErr: "a SPIFFE ID is required\n",
		},
		{
			name:   "Wrong SPIFFE ID",
			args:   []string{"-selector", "unix:uid:1", "-parentID", "spiffe://example.org/parent", "-spiffeID", "invalid-id"},
			expErr: "\"invalid-id\" is not a valid SPIFFE ID: invalid scheme\n",
		},
		{
			name:   "Wrong parent SPIFFE ID",
			args:   []string{"-selector", "unix:uid:1", "-parentID", "invalid-id", "-spiffeID", "spiffe://example.org/workload"},
			expErr: "\"invalid-id\" is not a valid SPIFFE ID: invalid scheme\n",
		},
		{
			name:   "Wrong selectors",
			args:   []string{"-selector", "unix", "-parentID", "spiffe://example.org/parent", "-spiffeID", "spiffe://example.org/workload"},
			expErr: "selector \"unix\" must be formatted as type:value\n",
		},
		{
			name:   "Negative TTL",
			args:   []string{"-selector", "unix", "-parentID", "spiffe://example.org/parent", "-spiffeID", "spiffe://example.org/workload", "-ttl", "-10"},
			expErr: "a positive TTL is required\n",
		},
		{
			name:   "Federated node entries",
			args:   []string{"-selector", "unix", "-spiffeID", "spiffe://example.org/workload", "-node", "-federatesWith", "spiffe://another.org"},
			expErr: "node entries can not federate\n",
		},
		{
			name:   "Wrong federated trust domain",
			args:   []string{"-selector", "unix", "-spiffeID", "spiffe://example.org/workload", "-parentID", "spiffe://example.org/parent", "-federatesWith", "invalid-id"},
			expErr: "\"invalid-id\" is not a valid SPIFFE ID: invalid scheme\n",
		},
		{
			name: "Server error",
			args: []string{"-spiffeID", "spiffe://example.org/node", "-node", "-selector", "unix:uid:1"},
			expReq: &entry.BatchCreateEntryRequest{Entries: []*types.Entry{
				{
					SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/node"},
					ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/server"},
					Selectors: []*types.Selector{{Type: "unix", Value: "uid:1"}},
				},
			}},
			serverErr: errors.New("server-error"),
			expErr:    "rpc error: code = Unknown desc = server-error\n",
		},
		{
			name: "Create succeeds using command line arguments",
			args: []string{
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
			expReq: &entry.BatchCreateEntryRequest{
				Entries: []*types.Entry{
					{
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
					},
				},
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
			name: "Create succeeds using data file",
			args: []string{
				"-data", "../../../../test/fixture/registration/good.json",
			},
			expReq: &entry.BatchCreateEntryRequest{
				Entries: []*types.Entry{
					{
						SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/Blog"},
						ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenBlog"},
						Selectors: []*types.Selector{{Type: "unix", Value: "uid:1111"}},
						Ttl:       200,
						Admin:     true,
					},
					{
						SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/Database"},
						ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenDatabase"},
						Selectors: []*types.Selector{{Type: "unix", Value: "uid:1111"}},
						Ttl:       200,
					},
				},
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
			name: "Entry already exist",
			args: []string{"-spiffeID", "spiffe://example.org/already-exist", "-node", "-selector", "unix:uid:1"},
			expReq: &entry.BatchCreateEntryRequest{Entries: []*types.Entry{
				{
					SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/already-exist"},
					ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/server"},
					Selectors: []*types.Selector{{Type: "unix", Value: "uid:1"}},
				},
			}},
			fakeResp: fakeRespErr,
			expOut: `FAILED to create the following entry:
Entry ID         : 
SPIFFE ID        : spiffe://example.org/already-exist
Parent ID        : spiffe://example.org/spire/server
Revision         : 0
TTL              : default
Selector         : unix:uid:1

similar entry already exists
`,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, newCreateCommand)
			test.server.err = tt.serverErr
			test.server.expBatchCreateEntryReq = tt.expReq
			test.server.batchCreateEntryResp = tt.fakeResp

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
