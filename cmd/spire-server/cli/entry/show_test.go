package entry

import (
	"fmt"
	"testing"
	"time"

	"github.com/spiffe/spire/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestShowHelp(t *testing.T) {
	test := setupTest(t, newShowCommand)
	test.client.Help()

	require.Equal(t, `Usage of entry show:
  -downstream
    	A boolean value that, when set, indicates that the entry describes a downstream SPIRE server
  -entryID string
    	The Entry ID of the records to show
  -federatesWith value
    	SPIFFE ID of a trust domain an entry is federate with. Can be used more than once
  -parentID string
    	The Parent ID of the records to show
  -registrationUDSPath string
    	Registration API UDS path (default "/tmp/spire-registration.sock")
  -selector value
    	A colon-delimited type:value selector. Can be used more than once
  -spiffeID string
    	The SPIFFE ID of the records to show
`, test.stderr.String())
}

func TestShowSynopsis(t *testing.T) {
	test := setupTest(t, newShowCommand)
	require.Equal(t, "Displays configured registration entries", test.client.Synopsis())
}

func TestShow(t *testing.T) {
	selectors := []*types.Selector{
		{Type: "foo", Value: "bar"},
		{Type: "bar", Value: "baz"},
		{Type: "baz", Value: "bat"},
	}

	entries := []*types.Entry{
		{
			ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent-1"},
			SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload-1"},
			Selectors: []*types.Selector{selectors[0]},
			Id:        "00000000-0000-0000-0000-000000000000",
		},
		{
			ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent-1"},
			SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload-2"},
			Selectors: []*types.Selector{selectors[0], selectors[1]},
			Id:        "00000000-0000-0000-0000-000000000001",
		},
		{
			ParentId:      &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent-2"},
			SpiffeId:      &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload-2"},
			Selectors:     []*types.Selector{selectors[1], selectors[2]},
			Id:            "00000000-0000-0000-0000-000000000002",
			FederatesWith: []string{"spiffe://domain.test"},
		},
		{
			ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent-2"},
			SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload-1"},
			Selectors: []*types.Selector{selectors[2]},
			ExpiresAt: 1552410266,
			Id:        "00000000-0000-0000-0000-000000000003",
		},
	}

	printedEntries := []string{`Entry ID         : 00000000-0000-0000-0000-000000000000
SPIFFE ID        : spiffe://example.org/workload-1
Parent ID        : spiffe://example.org/agent-1
Revision         : 0
TTL              : default
Selector         : foo:bar

`, `Entry ID         : 00000000-0000-0000-0000-000000000001
SPIFFE ID        : spiffe://example.org/workload-2
Parent ID        : spiffe://example.org/agent-1
Revision         : 0
TTL              : default
Selector         : bar:baz
Selector         : foo:bar

`, `Entry ID         : 00000000-0000-0000-0000-000000000002
SPIFFE ID        : spiffe://example.org/workload-2
Parent ID        : spiffe://example.org/agent-2
Revision         : 0
TTL              : default
Selector         : bar:baz
Selector         : baz:bat
FederatesWith    : spiffe://domain.test

`, fmt.Sprintf(`Entry ID         : 00000000-0000-0000-0000-000000000003
SPIFFE ID        : spiffe://example.org/workload-1
Parent ID        : spiffe://example.org/agent-2
Revision         : 0
TTL              : default
Expiration time  : %s
Selector         : baz:bat

`, time.Unix(1552410266, 0).UTC())}

	for _, tt := range []struct {
		name string
		args []string

		expListReq   *entry.ListEntriesRequest
		fakeListResp *entry.ListEntriesResponse
		expGetReq    *entry.GetEntryRequest
		fakeGetResp  *types.Entry

		serverErr error

		expOut string
		expErr string
	}{
		{
			name: "List all entries (empty filter)",
			expListReq: &entry.ListEntriesRequest{
				Filter: &entry.ListEntriesRequest_Filter{},
			},
			fakeListResp: &entry.ListEntriesResponse{
				Entries: []*types.Entry{entries[0], entries[1], entries[2], entries[3]},
			},
			expOut: fmt.Sprintf("Found 4 entries\n%s%s%s%s",
				printedEntries[0],
				printedEntries[3],
				printedEntries[1],
				printedEntries[2],
			),
		},
		{
			name:        "List by entry ID",
			args:        []string{"-entryID", entries[0].Id},
			expGetReq:   &entry.GetEntryRequest{Id: entries[0].Id},
			fakeGetResp: entries[0],
			expOut:      fmt.Sprintf("Found 1 entry\n%s", printedEntries[0]),
		},
		{
			name:      "List by entry ID not found",
			args:      []string{"-entryID", "non-existent-id"},
			expGetReq: &entry.GetEntryRequest{Id: "non-existent-id"},
			serverErr: status.Error(codes.NotFound, "no such registration entry"),
			expErr:    "Error: error fetching entry ID non-existent-id: rpc error: code = NotFound desc = no such registration entry\n",
		},
		{
			name:   "List by entry ID and other fields",
			args:   []string{"-entryID", "entry-id", "-spiffeID", "spiffe://example.org/workload"},
			expErr: "Error: the -entryID flag can't be combined with others\n",
		},
		{
			name: "List by parentID",
			args: []string{"-parentID", "spiffe://example.org/agent-1"},
			expListReq: &entry.ListEntriesRequest{
				Filter: &entry.ListEntriesRequest_Filter{
					ByParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent-1"},
				},
			},
			fakeListResp: &entry.ListEntriesResponse{
				Entries: []*types.Entry{entries[0], entries[1]},
			},
			expOut: fmt.Sprintf("Found 2 entries\n%s%s",
				printedEntries[0],
				printedEntries[1],
			),
		},
		{
			name:   "List by parent ID using invalid ID",
			args:   []string{"-parentID", "invalid-id"},
			expErr: "Error: error parsing parent ID \"invalid-id\": spiffeid: invalid scheme\n",
		},
		{
			name: "List by SPIFFE ID",
			args: []string{"-spiffeID", "spiffe://example.org/workload-2"},
			expListReq: &entry.ListEntriesRequest{
				Filter: &entry.ListEntriesRequest_Filter{
					BySpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload-2"},
				},
			},
			fakeListResp: &entry.ListEntriesResponse{Entries: []*types.Entry{entries[1], entries[2]}},
			expOut: fmt.Sprintf("Found 2 entries\n%s%s",
				printedEntries[1],
				printedEntries[2],
			),
		},
		{
			name:   "List by SPIFFE ID using invalid ID",
			args:   []string{"-spiffeID", "invalid-id"},
			expErr: "Error: error parsing SPIFFE ID \"invalid-id\": spiffeid: invalid scheme\n",
		},
		{
			name: "List by selectors",
			args: []string{"-selector", "foo:bar", "-selector", "bar:baz"},
			expListReq: &entry.ListEntriesRequest{
				Filter: &entry.ListEntriesRequest_Filter{
					BySelectors: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "foo", Value: "bar"},
							{Type: "bar", Value: "baz"},
						},
						Match: types.SelectorMatch_MATCH_EXACT,
					},
				},
			},
			fakeListResp: &entry.ListEntriesResponse{
				Entries: []*types.Entry{entries[1]},
			},
			expOut: fmt.Sprintf("Found 1 entry\n%s",
				printedEntries[1],
			),
		},
		{
			name:   "List by selector using invalid selector",
			args:   []string{"-selector", "invalid-selector"},
			expErr: "Error: error parsing selectors: selector \"invalid-selector\" must be formatted as type:value\n",
		},
		{
			name: "Server error",
			args: []string{"-spiffeID", "spiffe://example.org/workload-2"},
			expListReq: &entry.ListEntriesRequest{
				Filter: &entry.ListEntriesRequest_Filter{
					BySpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload-2"},
				},
			},
			serverErr: status.Error(codes.Internal, "internal server error"),
			expErr:    "Error: error fetching entries: rpc error: code = Internal desc = internal server error\n",
		},
		{
			name: "List by Federates With",
			args: []string{"-federatesWith", "spiffe://domain.test"},
			expListReq: &entry.ListEntriesRequest{
				Filter: &entry.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{"spiffe://domain.test"},
						Match:        types.FederatesWithMatch_MATCH_EXACT,
					},
				},
			},
			fakeListResp: &entry.ListEntriesResponse{
				Entries: []*types.Entry{entries[2]},
			},
			expOut: fmt.Sprintf("Found 1 entry\n%s",
				printedEntries[2],
			),
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, newShowCommand)
			test.server.err = tt.serverErr
			test.server.expListEntriesReq = tt.expListReq
			test.server.listEntriesResp = tt.fakeListResp
			test.server.expGetEntryReq = tt.expGetReq
			test.server.getEntryResp = tt.fakeGetResp

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
