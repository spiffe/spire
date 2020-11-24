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
	fakeRespAll := &entry.ListEntriesResponse{
		Entries: getEntries(4),
	}
	fakeRespFather := &entry.ListEntriesResponse{
		Entries: getEntries(2),
	}
	fakeRespDaughter := &entry.ListEntriesResponse{
		Entries: getEntries(3)[1:],
	}
	fakeRespFatherDaughter := &entry.ListEntriesResponse{
		Entries: getEntries(2)[1:],
	}

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
			fakeListResp: fakeRespAll,
			expOut: fmt.Sprintf("Found 4 entries\n%s%s%s%s",
				getPrintedEntry(1),
				getPrintedEntry(2),
				getPrintedEntry(0),
				getPrintedEntry(3),
			),
		},
		{
			name:        "List by entry ID",
			args:        []string{"-entryID", getEntries(1)[0].Id},
			expGetReq:   &entry.GetEntryRequest{Id: getEntries(1)[0].Id},
			fakeGetResp: getEntries(1)[0],
			expOut:      fmt.Sprintf("Found 1 entry\n%s", getPrintedEntry(0)),
		},
		{
			name:      "List by entry ID not found",
			args:      []string{"-entryID", "non-existent-id"},
			expGetReq: &entry.GetEntryRequest{Id: "non-existent-id"},
			serverErr: status.Error(codes.NotFound, "no such registration entry"),
			expErr:    "error fetching entry ID non-existent-id: rpc error: code = NotFound desc = no such registration entry\n",
		},
		{
			name:   "List by entry ID and other fields",
			args:   []string{"-entryID", "entry-id", "-spiffeID", "spiffe://example.org/workload"},
			expErr: "the -entryID flag can't be combined with others\n",
		},
		{
			name: "List by parentID",
			args: []string{"-parentID", "spiffe://example.org/father"},
			expListReq: &entry.ListEntriesRequest{
				Filter: &entry.ListEntriesRequest_Filter{
					ByParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/father"},
				},
			},
			fakeListResp: fakeRespFather,
			expOut: fmt.Sprintf("Found 2 entries\n%s%s",
				getPrintedEntry(1),
				getPrintedEntry(0),
			),
		},
		{
			name:   "List by parent ID using invalid ID",
			args:   []string{"-parentID", "invalid-id"},
			expErr: "error parsing parent ID \"invalid-id\": spiffeid: invalid scheme\n",
		},
		{
			name: "List by SPIFFE ID",
			args: []string{"-spiffeID", "spiffe://example.org/daughter"},
			expListReq: &entry.ListEntriesRequest{
				Filter: &entry.ListEntriesRequest_Filter{
					BySpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/daughter"},
				},
			},
			fakeListResp: fakeRespDaughter,
			expOut: fmt.Sprintf("Found 2 entries\n%s%s",
				getPrintedEntry(1),
				getPrintedEntry(2),
			),
		},
		{
			name:   "List by SPIFFE ID using invalid ID",
			args:   []string{"-spiffeID", "invalid-id"},
			expErr: "error parsing SPIFFE ID \"invalid-id\": spiffeid: invalid scheme\n",
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
			fakeListResp: fakeRespFatherDaughter,
			expOut: fmt.Sprintf("Found 1 entry\n%s",
				getPrintedEntry(1),
			),
		},
		{
			name:   "List by selector using invalid selector",
			args:   []string{"-selector", "invalid-selector"},
			expErr: "error parsing selectors: selector \"invalid-selector\" must be formatted as type:value\n",
		},
		{
			name: "Server error",
			args: []string{"-spiffeID", "spiffe://example.org/daughter"},
			expListReq: &entry.ListEntriesRequest{
				Filter: &entry.ListEntriesRequest_Filter{
					BySpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/daughter"},
				},
			},
			serverErr: status.Error(codes.Internal, "internal server error"),
			expErr:    "error fetching entries: rpc error: code = Internal desc = internal server error\n",
		},
		{
			name: "List by Federates With",
			args: []string{"-federatesWith", "spiffe://domain.test"},
			expListReq: &entry.ListEntriesRequest{
				// Filter is empty because federatesWith filtering is done on the client side
				Filter: &entry.ListEntriesRequest_Filter{},
			},
			fakeListResp: fakeRespAll,
			expOut: fmt.Sprintf("Found 1 entry\n%s",
				getPrintedEntry(2),
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

// registrationEntries returns `count` registration entry records. At most 4.
func getEntries(count int) []*types.Entry {
	selectors := []*types.Selector{
		{Type: "foo", Value: "bar"},
		{Type: "bar", Value: "baz"},
		{Type: "baz", Value: "bat"},
	}
	entries := []*types.Entry{
		{
			ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/father"},
			SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/son"},
			Selectors: []*types.Selector{selectors[0]},
			Id:        "00000000-0000-0000-0000-000000000000",
		},
		{
			ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/father"},
			SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/daughter"},
			Selectors: []*types.Selector{selectors[0], selectors[1]},
			Id:        "00000000-0000-0000-0000-000000000001",
		},
		{
			ParentId:      &types.SPIFFEID{TrustDomain: "example.org", Path: "/mother"},
			SpiffeId:      &types.SPIFFEID{TrustDomain: "example.org", Path: "/daughter"},
			Selectors:     []*types.Selector{selectors[1], selectors[2]},
			Id:            "00000000-0000-0000-0000-000000000002",
			FederatesWith: []string{"spiffe://domain.test"},
		},
		{
			ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/mother"},
			SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/son"},
			Selectors: []*types.Selector{selectors[2]},
			ExpiresAt: 1552410266,
			Id:        "00000000-0000-0000-0000-000000000003",
		},
	}

	e := []*types.Entry{}
	for i := 0; i < count; i++ {
		e = append(e, entries[i])
	}

	return e
}

func getPrintedEntry(idx int) string {
	switch idx {
	case 0:
		return `Entry ID         : 00000000-0000-0000-0000-000000000000
SPIFFE ID        : spiffe://example.org/son
Parent ID        : spiffe://example.org/father
Revision         : 0
TTL              : default
Selector         : foo:bar

`
	case 1:
		return `Entry ID         : 00000000-0000-0000-0000-000000000001
SPIFFE ID        : spiffe://example.org/daughter
Parent ID        : spiffe://example.org/father
Revision         : 0
TTL              : default
Selector         : bar:baz
Selector         : foo:bar

`
	case 2:
		return `Entry ID         : 00000000-0000-0000-0000-000000000002
SPIFFE ID        : spiffe://example.org/daughter
Parent ID        : spiffe://example.org/mother
Revision         : 0
TTL              : default
Selector         : bar:baz
Selector         : baz:bat
FederatesWith    : spiffe://domain.test

`
	case 3:
		return fmt.Sprintf(`Entry ID         : 00000000-0000-0000-0000-000000000003
SPIFFE ID        : spiffe://example.org/son
Parent ID        : spiffe://example.org/mother
Revision         : 0
TTL              : default
Expiration time  : %s
Selector         : baz:bat

`, time.Unix(1552410266, 0).UTC())
	default:
		return "index should be lower than 4"
	}
}
