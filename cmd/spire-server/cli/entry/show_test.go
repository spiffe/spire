package entry

import (
	"fmt"
	"testing"
	"time"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestShowHelp(t *testing.T) {
	test := setupTest(t, newShowCommand)
	test.client.Help()

	require.Equal(t, showUsage, test.stderr.String())
}

func TestShowSynopsis(t *testing.T) {
	test := setupTest(t, newShowCommand)
	require.Equal(t, "Displays configured registration entries", test.client.Synopsis())
}

func TestShow(t *testing.T) {
	fakeRespAll := &entryv1.ListEntriesResponse{
		Entries: getEntries(4),
	}
	fakeRespFather := &entryv1.ListEntriesResponse{
		Entries: getEntries(2),
	}
	fakeRespDaughter := &entryv1.ListEntriesResponse{
		Entries: getEntries(3)[1:],
	}
	fakeRespFatherDaughter := &entryv1.ListEntriesResponse{
		Entries: getEntries(2)[1:],
	}

	fakeRespMotherDaughter := &entryv1.ListEntriesResponse{
		Entries: getEntries(3)[2:],
	}

	for _, tt := range []struct {
		name string
		args []string

		expListReq   *entryv1.ListEntriesRequest
		fakeListResp *entryv1.ListEntriesResponse
		expGetReq    *entryv1.GetEntryRequest
		fakeGetResp  *types.Entry

		serverErr error

		expOutPretty string
		expOutJSON   string
		expErr       string
	}{
		{
			name: "List all entries (empty filter)",
			expListReq: &entryv1.ListEntriesRequest{
				PageSize: listEntriesRequestPageSize,
				Filter:   &entryv1.ListEntriesRequest_Filter{},
			},
			fakeListResp: fakeRespAll,
			expOutPretty: fmt.Sprintf("Found 4 entries\n%s%s%s%s",
				getPrettyPrintedEntry(1),
				getPrettyPrintedEntry(2),
				getPrettyPrintedEntry(0),
				getPrettyPrintedEntry(3),
			),
			expOutJSON: fmt.Sprintf(`{"entries": [%s,%s,%s,%s],"next_page_token": ""}`,
				getJSONPrintedEntry(1),
				getJSONPrintedEntry(2),
				getJSONPrintedEntry(0),
				getJSONPrintedEntry(3),
			),
		},
		{
			name:         "List by entry ID",
			args:         []string{"-entryID", getEntries(1)[0].Id},
			expGetReq:    &entryv1.GetEntryRequest{Id: getEntries(1)[0].Id},
			fakeGetResp:  getEntries(1)[0],
			expOutPretty: fmt.Sprintf("Found 1 entry\n%s", getPrettyPrintedEntry(0)),
			expOutJSON:   fmt.Sprintf(`{"entries": [%s],"next_page_token": ""}`, getJSONPrintedEntry(0)),
		},
		{
			name:      "List by entry ID not found",
			args:      []string{"-entryID", "non-existent-id"},
			expGetReq: &entryv1.GetEntryRequest{Id: "non-existent-id"},
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
			args: []string{"-parentID", "spiffe://example.org/father"},
			expListReq: &entryv1.ListEntriesRequest{
				PageSize: listEntriesRequestPageSize,
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/father"},
				},
			},
			fakeListResp: fakeRespFather,
			expOutPretty: fmt.Sprintf("Found 2 entries\n%s%s",
				getPrettyPrintedEntry(1),
				getPrettyPrintedEntry(0),
			),
			expOutJSON: fmt.Sprintf(`{"entries": [%s,%s],"next_page_token": ""}`, getJSONPrintedEntry(1), getJSONPrintedEntry(0)),
		},
		{
			name:   "List by parent ID using invalid ID",
			args:   []string{"-parentID", "invalid-id"},
			expErr: "Error: error parsing parent ID \"invalid-id\": scheme is missing or invalid\n",
		},
		{
			name: "List by SPIFFE ID",
			args: []string{"-spiffeID", "spiffe://example.org/daughter"},
			expListReq: &entryv1.ListEntriesRequest{
				PageSize: listEntriesRequestPageSize,
				Filter: &entryv1.ListEntriesRequest_Filter{
					BySpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/daughter"},
				},
			},
			fakeListResp: fakeRespDaughter,
			expOutPretty: fmt.Sprintf("Found 2 entries\n%s%s",
				getPrettyPrintedEntry(1),
				getPrettyPrintedEntry(2),
			),
			expOutJSON: fmt.Sprintf(`{"entries": [%s, %s],"next_page_token": ""}`, getJSONPrintedEntry(1), getJSONPrintedEntry(2)),
		},
		{
			name:   "List by SPIFFE ID using invalid ID",
			args:   []string{"-spiffeID", "invalid-id"},
			expErr: "Error: error parsing SPIFFE ID \"invalid-id\": scheme is missing or invalid\n",
		},
		{
			name: "List by selectors: default matcher",
			args: []string{"-selector", "foo:bar", "-selector", "bar:baz"},
			expListReq: &entryv1.ListEntriesRequest{
				PageSize: listEntriesRequestPageSize,
				Filter: &entryv1.ListEntriesRequest_Filter{
					BySelectors: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "foo", Value: "bar"},
							{Type: "bar", Value: "baz"},
						},
						Match: types.SelectorMatch_MATCH_SUPERSET,
					},
				},
			},
			fakeListResp: fakeRespFatherDaughter,
			expOutPretty: fmt.Sprintf("Found 1 entry\n%s",
				getPrettyPrintedEntry(1),
			),
			expOutJSON: fmt.Sprintf(`{"entries": [%s],"next_page_token": ""}`, getJSONPrintedEntry(1)),
		},
		{
			name: "List by selectors: exact matcher",
			args: []string{"-selector", "foo:bar", "-selector", "bar:baz", "-matchSelectorsOn", "exact"},
			expListReq: &entryv1.ListEntriesRequest{
				PageSize: listEntriesRequestPageSize,
				Filter: &entryv1.ListEntriesRequest_Filter{
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
			expOutPretty: fmt.Sprintf("Found 1 entry\n%s",
				getPrettyPrintedEntry(1),
			),
			expOutJSON: fmt.Sprintf(`{"entries": [%s],"next_page_token": ""}`, getJSONPrintedEntry(1)),
		},
		{
			name: "List by selectors: superset matcher",
			args: []string{"-selector", "foo:bar", "-selector", "bar:baz", "-matchSelectorsOn", "superset"},
			expListReq: &entryv1.ListEntriesRequest{
				PageSize: listEntriesRequestPageSize,
				Filter: &entryv1.ListEntriesRequest_Filter{
					BySelectors: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "foo", Value: "bar"},
							{Type: "bar", Value: "baz"},
						},
						Match: types.SelectorMatch_MATCH_SUPERSET,
					},
				},
			},
			fakeListResp: fakeRespFatherDaughter,
			expOutPretty: fmt.Sprintf("Found 1 entry\n%s",
				getPrettyPrintedEntry(1),
			),
			expOutJSON: fmt.Sprintf(`{"entries": [%s],"next_page_token": ""}`, getJSONPrintedEntry(1)),
		},
		{
			name: "List by selectors: subset matcher",
			args: []string{"-selector", "foo:bar", "-selector", "bar:baz", "-matchSelectorsOn", "subset"},
			expListReq: &entryv1.ListEntriesRequest{
				PageSize: listEntriesRequestPageSize,
				Filter: &entryv1.ListEntriesRequest_Filter{
					BySelectors: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "foo", Value: "bar"},
							{Type: "bar", Value: "baz"},
						},
						Match: types.SelectorMatch_MATCH_SUBSET,
					},
				},
			},
			fakeListResp: fakeRespFatherDaughter,
			expOutPretty: fmt.Sprintf("Found 1 entry\n%s",
				getPrettyPrintedEntry(1),
			),
			expOutJSON: fmt.Sprintf(`{"entries": [%s],"next_page_token": ""}`, getJSONPrintedEntry(1)),
		},
		{
			name: "List by selectors: Any matcher",
			args: []string{"-selector", "foo:bar", "-selector", "bar:baz", "-matchSelectorsOn", "any"},
			expListReq: &entryv1.ListEntriesRequest{
				PageSize: listEntriesRequestPageSize,
				Filter: &entryv1.ListEntriesRequest_Filter{
					BySelectors: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "foo", Value: "bar"},
							{Type: "bar", Value: "baz"},
						},
						Match: types.SelectorMatch_MATCH_ANY,
					},
				},
			},
			fakeListResp: fakeRespFatherDaughter,
			expOutPretty: fmt.Sprintf("Found 1 entry\n%s",
				getPrettyPrintedEntry(1),
			),
			expOutJSON: fmt.Sprintf(`{"entries": [%s],"next_page_token": ""}`, getJSONPrintedEntry(1)),
		},
		{
			name:   "List by selectors: Invalid matcher",
			args:   []string{"-selector", "foo:bar", "-selector", "bar:baz", "-matchSelectorsOn", "NO-MATCHER"},
			expErr: "Error: match behavior \"NO-MATCHER\" unknown\n",
		},
		{
			name:   "List by selector using invalid selector",
			args:   []string{"-selector", "invalid-selector"},
			expErr: "Error: error parsing selectors: selector \"invalid-selector\" must be formatted as type:value\n",
		},
		{
			name: "Server error",
			args: []string{"-spiffeID", "spiffe://example.org/daughter"},
			expListReq: &entryv1.ListEntriesRequest{
				PageSize: listEntriesRequestPageSize,
				Filter: &entryv1.ListEntriesRequest_Filter{
					BySpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/daughter"},
				},
			},
			serverErr: status.Error(codes.Internal, "internal server error"),
			expErr:    "Error: error fetching entries: rpc error: code = Internal desc = internal server error\n",
		},
		{
			name: "List by Federates With: default matcher",
			args: []string{"-federatesWith", "spiffe://domain.test"},
			expListReq: &entryv1.ListEntriesRequest{
				PageSize: listEntriesRequestPageSize,
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{"spiffe://domain.test"},
						Match:        types.FederatesWithMatch_MATCH_SUPERSET,
					},
				},
			},
			fakeListResp: fakeRespMotherDaughter,
			expOutPretty: fmt.Sprintf("Found 1 entry\n%s",
				getPrettyPrintedEntry(2),
			),
			expOutJSON: fmt.Sprintf(`{"entries": [%s],"next_page_token": ""}`, getJSONPrintedEntry(2)),
		},
		{
			name: "List by Federates With: exact matcher",
			args: []string{"-federatesWith", "spiffe://domain.test", "-matchFederatesWithOn", "exact"},
			expListReq: &entryv1.ListEntriesRequest{
				PageSize: listEntriesRequestPageSize,
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{"spiffe://domain.test"},
						Match:        types.FederatesWithMatch_MATCH_EXACT,
					},
				},
			},
			fakeListResp: fakeRespMotherDaughter,
			expOutPretty: fmt.Sprintf("Found 1 entry\n%s",
				getPrettyPrintedEntry(2),
			),
			expOutJSON: fmt.Sprintf(`{"entries": [%s],"next_page_token": ""}`, getJSONPrintedEntry(2)),
		},
		{
			name: "List by Federates With: Any matcher",
			args: []string{"-federatesWith", "spiffe://domain.test", "-matchFederatesWithOn", "any"},
			expListReq: &entryv1.ListEntriesRequest{
				PageSize: listEntriesRequestPageSize,
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{"spiffe://domain.test"},
						Match:        types.FederatesWithMatch_MATCH_ANY,
					},
				},
			},
			fakeListResp: fakeRespMotherDaughter,
			expOutPretty: fmt.Sprintf("Found 1 entry\n%s",
				getPrettyPrintedEntry(2),
			),
			expOutJSON: fmt.Sprintf(`{"entries": [%s],"next_page_token": ""}`, getJSONPrintedEntry(2)),
		},
		{
			name: "List by Federates With: superset matcher",
			args: []string{"-federatesWith", "spiffe://domain.test", "-matchFederatesWithOn", "superset"},
			expListReq: &entryv1.ListEntriesRequest{
				PageSize: listEntriesRequestPageSize,
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{"spiffe://domain.test"},
						Match:        types.FederatesWithMatch_MATCH_SUPERSET,
					},
				},
			},
			fakeListResp: fakeRespMotherDaughter,
			expOutPretty: fmt.Sprintf("Found 1 entry\n%s",
				getPrettyPrintedEntry(2),
			),
			expOutJSON: fmt.Sprintf(`{"entries": [%s],"next_page_token": ""}`, getJSONPrintedEntry(2)),
		},
		{
			name: "List by Federates With: subset matcher",
			args: []string{"-federatesWith", "spiffe://domain.test", "-matchFederatesWithOn", "subset"},
			expListReq: &entryv1.ListEntriesRequest{
				PageSize: listEntriesRequestPageSize,
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{"spiffe://domain.test"},
						Match:        types.FederatesWithMatch_MATCH_SUBSET,
					},
				},
			},
			fakeListResp: fakeRespMotherDaughter,
			expOutPretty: fmt.Sprintf("Found 1 entry\n%s",
				getPrettyPrintedEntry(2),
			),
			expOutJSON: fmt.Sprintf(`{"entries": [%s],"next_page_token": ""}`, getJSONPrintedEntry(2)),
		},
		{
			name:   "List by Federates With: Invalid matcher",
			args:   []string{"-federatesWith", "spiffe://domain.test", "-matchFederatesWithOn", "NO-MATCHER"},
			expErr: "Error: match behavior \"NO-MATCHER\" unknown\n",
		},
	} {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, newShowCommand)
				test.server.err = tt.serverErr
				test.server.expListEntriesReq = tt.expListReq
				test.server.listEntriesResp = tt.fakeListResp
				test.server.expGetEntryReq = tt.expGetReq
				test.server.getEntryResp = tt.fakeGetResp
				args := tt.args
				args = append(args, "-output", format)

				rc := test.client.Run(test.args(args...))
				if tt.expErr != "" {
					require.Equal(t, 1, rc)
					require.Equal(t, tt.expErr, test.stderr.String())
					return
				}
				requireOutputBasedOnFormat(t, format, test.stdout.String(), tt.expOutPretty, tt.expOutJSON)
				require.Equal(t, 0, rc)
			})
		}
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

func getPrettyPrintedEntry(idx int) string {
	switch idx {
	case 0:
		return `Entry ID         : 00000000-0000-0000-0000-000000000000
SPIFFE ID        : spiffe://example.org/son
Parent ID        : spiffe://example.org/father
Revision         : 0
X509-SVID TTL    : default
JWT-SVID TTL     : default
Selector         : foo:bar

`
	case 1:
		return `Entry ID         : 00000000-0000-0000-0000-000000000001
SPIFFE ID        : spiffe://example.org/daughter
Parent ID        : spiffe://example.org/father
Revision         : 0
X509-SVID TTL    : default
JWT-SVID TTL     : default
Selector         : bar:baz
Selector         : foo:bar

`
	case 2:
		return `Entry ID         : 00000000-0000-0000-0000-000000000002
SPIFFE ID        : spiffe://example.org/daughter
Parent ID        : spiffe://example.org/mother
Revision         : 0
X509-SVID TTL    : default
JWT-SVID TTL     : default
Selector         : bar:baz
Selector         : baz:bat
FederatesWith    : spiffe://domain.test

`
	case 3:
		return fmt.Sprintf(`Entry ID         : 00000000-0000-0000-0000-000000000003
SPIFFE ID        : spiffe://example.org/son
Parent ID        : spiffe://example.org/mother
Revision         : 0
X509-SVID TTL    : default
JWT-SVID TTL     : default
Expiration time  : %s
Selector         : baz:bat

`, time.Unix(1552410266, 0).UTC())
	default:
		return "index should be lower than 4"
	}
}

func getJSONPrintedEntry(idx int) string {
	switch idx {
	case 0:
		return `{
      "id": "00000000-0000-0000-0000-000000000000",
      "spiffe_id": {
        "trust_domain": "example.org",
        "path": "/son"
      },
      "parent_id": {
        "trust_domain": "example.org",
        "path": "/father"
      },
      "selectors": [
        {
          "type": "foo",
          "value": "bar"
        }
      ],
      "x509_svid_ttl": 0,
      "federates_with": [],
      "admin": false,
      "downstream": false,
      "expires_at": "0",
      "dns_names": [],
      "revision_number": "0",
      "store_svid": false,
      "jwt_svid_ttl": 0
    }`
	case 1:
		return `{
      "id": "00000000-0000-0000-0000-000000000001",
      "spiffe_id": {
        "trust_domain": "example.org",
        "path": "/daughter"
      },
      "parent_id": {
        "trust_domain": "example.org",
        "path": "/father"
      },
      "selectors": [
        {
          "type": "bar",
          "value": "baz"
        },
        {
          "type": "foo",
          "value": "bar"
        }
      ],
      "x509_svid_ttl": 0,
      "federates_with": [],
      "admin": false,
      "downstream": false,
      "expires_at": "0",
      "dns_names": [],
      "revision_number": "0",
      "store_svid": false,
      "jwt_svid_ttl": 0
    }`
	case 2:
		return `{
      "id": "00000000-0000-0000-0000-000000000002",
      "spiffe_id": {
        "trust_domain": "example.org",
        "path": "/daughter"
      },
      "parent_id": {
        "trust_domain": "example.org",
        "path": "/mother"
      },
      "selectors": [
        {
          "type": "bar",
          "value": "baz"
        },
        {
          "type": "baz",
          "value": "bat"
        }
      ],
      "x509_svid_ttl": 0,
      "federates_with": [
        "spiffe://domain.test"
      ],
      "admin": false,
      "downstream": false,
      "expires_at": "0",
      "dns_names": [],
      "revision_number": "0",
      "store_svid": false,
      "jwt_svid_ttl": 0
    }`
	case 3:
		return `{
      "id": "00000000-0000-0000-0000-000000000003",
      "spiffe_id": {
        "trust_domain": "example.org",
        "path": "/son"
      },
      "parent_id": {
        "trust_domain": "example.org",
        "path": "/mother"
      },
      "selectors": [
        {
          "type": "baz",
          "value": "bat"
        }
      ],
      "x509_svid_ttl": 0,
      "federates_with": [],
      "admin": false,
      "downstream": false,
      "expires_at": "1552410266",
      "dns_names": [],
      "revision_number": "0",
      "store_svid": false,
      "jwt_svid_ttl": 0
    }`
	default:
		return "index should be lower than 4"
	}
}
