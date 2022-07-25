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

func TestCreateHelp(t *testing.T) {
	test := setupTest(t, newCreateCommand)
	test.client.Help()

	require.Equal(t, createUsage, test.stderr.String())
}

func TestCreateSynopsis(t *testing.T) {
	test := setupTest(t, newCreateCommand)
	require.Equal(t, "Creates registration entries", test.client.Synopsis())
}

func TestCreate(t *testing.T) {
	fakeRespOKFromCmd := &entryv1.BatchCreateEntryResponse{
		Results: []*entryv1.BatchCreateEntryResponse_Result{
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
					StoreSvid:     true,
				},
				Status: &types.Status{
					Code:    int32(codes.OK),
					Message: "OK",
				},
			},
		},
	}

	fakeRespOKFromFile := &entryv1.BatchCreateEntryResponse{
		Results: []*entryv1.BatchCreateEntryResponse_Result{
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
			{
				Entry: &types.Entry{
					Id:       "entry-id-3",
					SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/storesvid"},
					ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenDatabase"},
					Selectors: []*types.Selector{
						{Type: "type", Value: "key1:value"},
						{Type: "type", Value: "key2:value"},
					},
					StoreSvid: true,
					Ttl:       200,
				},
				Status: &types.Status{
					Code:    int32(codes.OK),
					Message: "OK",
				},
			},
		},
	}

	fakeRespErr := &entryv1.BatchCreateEntryResponse{
		Results: []*entryv1.BatchCreateEntryResponse_Result{
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

		expReq    *entryv1.BatchCreateEntryRequest
		fakeResp  *entryv1.BatchCreateEntryResponse
		serverErr error

		expOut string
		expErr string
	}{
		{
			name:   "Missing selectors",
			expErr: "Error: at least one selector is required\n",
		},
		{
			name:   "Missing parent SPIFFE ID",
			args:   []string{"-selector", "unix:uid:1"},
			expErr: "Error: a parent ID is required if the node flag is not set\n",
		},
		{
			name:   "Missing SPIFFE ID",
			args:   []string{"-selector", "unix:uid:1", "-parentID", "spiffe://example.org/parent"},
			expErr: "Error: a SPIFFE ID is required\n",
		},
		{
			name:   "Wrong selectors",
			args:   []string{"-selector", "unix", "-parentID", "spiffe://example.org/parent", "-spiffeID", "spiffe://example.org/workload"},
			expErr: "Error: selector \"unix\" must be formatted as type:value\n",
		},
		{
			name:   "Negative TTL",
			args:   []string{"-selector", "unix", "-parentID", "spiffe://example.org/parent", "-spiffeID", "spiffe://example.org/workload", "-ttl", "-10"},
			expErr: "Error: a positive TTL is required\n",
		},
		{
			name:   "Federated node entries",
			args:   []string{"-selector", "unix", "-spiffeID", "spiffe://example.org/workload", "-node", "-federatesWith", "spiffe://another.org"},
			expErr: "Error: node entries can not federate\n",
		},
		{
			name: "Server error",
			args: []string{"-spiffeID", "spiffe://example.org/node", "-node", "-selector", "unix:uid:1"},
			expReq: &entryv1.BatchCreateEntryRequest{Entries: []*types.Entry{
				{
					SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/node"},
					ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/server"},
					Selectors: []*types.Selector{{Type: "unix", Value: "uid:1"}},
				},
			}},
			serverErr: errors.New("server-error"),
			expErr:    "Error: rpc error: code = Unknown desc = server-error\n",
		},
		{
			name: "Create succeeds using command line arguments",
			args: []string{
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
				"-storeSVID",
			},
			expReq: &entryv1.BatchCreateEntryRequest{
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
						StoreSvid:     true,
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
StoreSvid        : true

`, time.Unix(1552410266, 0).UTC()),
		},
		{
			name: "Create succeeds using data file",
			args: []string{
				"-data", "../../../../test/fixture/registration/good.json",
			},
			expReq: &entryv1.BatchCreateEntryRequest{
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
					{
						SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/storesvid"},
						ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenDatabase"},
						Selectors: []*types.Selector{
							{Type: "type", Value: "key1:value"},
							{Type: "type", Value: "key2:value"},
						},
						Ttl:       200,
						StoreSvid: true,
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

Entry ID         : entry-id-3
SPIFFE ID        : spiffe://example.org/storesvid
Parent ID        : spiffe://example.org/spire/agent/join_token/TokenDatabase
Revision         : 0
TTL              : 200
Selector         : type:key1:value
Selector         : type:key2:value
StoreSvid        : true

`,
		},
		{
			name: "Entry already exist",
			args: []string{"-spiffeID", "spiffe://example.org/already-exist", "-node", "-selector", "unix:uid:1"},
			expReq: &entryv1.BatchCreateEntryRequest{Entries: []*types.Entry{
				{
					SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/already-exist"},
					ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/server"},
					Selectors: []*types.Selector{{Type: "unix", Value: "uid:1"}},
				},
			}},
			fakeResp: fakeRespErr,
			expErr: `Failed to create the following entry (code: AlreadyExists, msg: "similar entry already exists"):
Entry ID         : (none)
SPIFFE ID        : spiffe://example.org/already-exist
Parent ID        : spiffe://example.org/spire/server
Revision         : 0
TTL              : default
Selector         : unix:uid:1

Error: failed to create one or more entries
`,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, newCreateCommand)
			test.server.err = tt.serverErr
			test.server.expBatchCreateEntryReq = tt.expReq
			test.server.batchCreateEntryResp = tt.fakeResp

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
