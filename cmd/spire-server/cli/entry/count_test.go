package entry

import (
	"fmt"
	"testing"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestCountHelp(t *testing.T) {
	test := setupTest(t, NewCountCommandWithEnv)
	test.client.Help()

	require.Equal(t, countUsage, test.stderr.String())
}

func TestCountSynopsis(t *testing.T) {
	test := setupTest(t, NewCountCommandWithEnv)
	require.Equal(t, "Count registration entries", test.client.Synopsis())
}

func TestCount(t *testing.T) {
	fakeResp4 := &entryv1.CountEntriesResponse{Count: 4}
	fakeResp2 := &entryv1.CountEntriesResponse{Count: 2}
	fakeResp1 := &entryv1.CountEntriesResponse{Count: 1}
	fakeResp0 := &entryv1.CountEntriesResponse{Count: 0}

	for _, tt := range []struct {
		name          string
		args          []string
		expCountReq   *entryv1.CountEntriesRequest
		fakeCountResp *entryv1.CountEntriesResponse
		serverErr     error
		expOutPretty  string
		expOutJSON    string
		expErr        string
	}{
		{
			name: "Count all entries (empty filter)",
			expCountReq: &entryv1.CountEntriesRequest{
				Filter: &entryv1.CountEntriesRequest_Filter{
					ByDownstream: wrapperspb.Bool(false),
				},
			},
			fakeCountResp: fakeResp4,
			expOutPretty:  "4 registration entries",
			expOutJSON:    `{"count":4}`,
		},
		{
			name: "Count by parentID",
			args: []string{"-parentID", "spiffe://example.org/father"},
			expCountReq: &entryv1.CountEntriesRequest{
				Filter: &entryv1.CountEntriesRequest_Filter{
					ByParentId:   &types.SPIFFEID{TrustDomain: "example.org", Path: "/father"},
					ByDownstream: wrapperspb.Bool(false),
				},
			},
			fakeCountResp: fakeResp2,
			expOutPretty:  "2 registration entries",
			expOutJSON:    `{"count":2}`,
		},
		{
			name:   "Count by parent ID using invalid ID",
			args:   []string{"-parentID", "invalid-id"},
			expErr: "Error: error parsing parent ID \"invalid-id\": scheme is missing or invalid\n",
		},
		{
			name: "Count by SPIFFE ID",
			args: []string{"-spiffeID", "spiffe://example.org/daughter"},
			expCountReq: &entryv1.CountEntriesRequest{
				Filter: &entryv1.CountEntriesRequest_Filter{
					BySpiffeId:   &types.SPIFFEID{TrustDomain: "example.org", Path: "/daughter"},
					ByDownstream: wrapperspb.Bool(false),
				},
			},
			fakeCountResp: fakeResp2,
			expOutPretty:  "2 registration entries",
			expOutJSON:    `{"count":2}`,
		},
		{
			name:   "Count by SPIFFE ID using invalid ID",
			args:   []string{"-spiffeID", "invalid-id"},
			expErr: "Error: error parsing SPIFFE ID \"invalid-id\": scheme is missing or invalid\n",
		},
		{
			name: "Count by selectors: default matcher",
			args: []string{"-selector", "foo:bar", "-selector", "bar:baz"},
			expCountReq: &entryv1.CountEntriesRequest{
				Filter: &entryv1.CountEntriesRequest_Filter{
					BySelectors: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "foo", Value: "bar"},
							{Type: "bar", Value: "baz"},
						},
						Match: types.SelectorMatch_MATCH_SUPERSET,
					},
					ByDownstream: wrapperspb.Bool(false),
				},
			},
			fakeCountResp: fakeResp1,
			expOutPretty:  "1 registration entry",
			expOutJSON:    `{"count":1}`,
		},
		{
			name: "Count by selectors: exact matcher",
			args: []string{"-selector", "foo:bar", "-selector", "bar:baz", "-matchSelectorsOn", "exact"},
			expCountReq: &entryv1.CountEntriesRequest{
				Filter: &entryv1.CountEntriesRequest_Filter{
					BySelectors: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "foo", Value: "bar"},
							{Type: "bar", Value: "baz"},
						},
						Match: types.SelectorMatch_MATCH_EXACT,
					},
					ByDownstream: wrapperspb.Bool(false),
				},
			},
			fakeCountResp: fakeResp1,
			expOutPretty:  "1 registration entry",
			expOutJSON:    `{"count":1}`,
		},
		{
			name: "Count by selectors: superset matcher",
			args: []string{"-selector", "foo:bar", "-selector", "bar:baz", "-matchSelectorsOn", "superset"},
			expCountReq: &entryv1.CountEntriesRequest{
				Filter: &entryv1.CountEntriesRequest_Filter{
					BySelectors: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "foo", Value: "bar"},
							{Type: "bar", Value: "baz"},
						},
						Match: types.SelectorMatch_MATCH_SUPERSET,
					},
					ByDownstream: wrapperspb.Bool(false),
				},
			},
			fakeCountResp: fakeResp1,
			expOutPretty:  "1 registration entry",
			expOutJSON:    `{"count":1}`,
		},
		{
			name: "Count by selectors: subset matcher",
			args: []string{"-selector", "foo:bar", "-selector", "bar:baz", "-matchSelectorsOn", "subset"},
			expCountReq: &entryv1.CountEntriesRequest{
				Filter: &entryv1.CountEntriesRequest_Filter{
					BySelectors: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "foo", Value: "bar"},
							{Type: "bar", Value: "baz"},
						},
						Match: types.SelectorMatch_MATCH_SUBSET,
					},
					ByDownstream: wrapperspb.Bool(false),
				},
			},
			fakeCountResp: fakeResp1,
			expOutPretty:  "1 registration entry",
			expOutJSON:    `{"count":1}`,
		},
		{
			name: "Count by selectors: Any matcher",
			args: []string{"-selector", "foo:bar", "-selector", "bar:baz", "-matchSelectorsOn", "any"},
			expCountReq: &entryv1.CountEntriesRequest{
				Filter: &entryv1.CountEntriesRequest_Filter{
					BySelectors: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "foo", Value: "bar"},
							{Type: "bar", Value: "baz"},
						},
						Match: types.SelectorMatch_MATCH_ANY,
					},
					ByDownstream: wrapperspb.Bool(false),
				},
			},
			fakeCountResp: fakeResp1,
			expOutPretty:  "1 registration entry",
			expOutJSON:    `{"count":1}`,
		},
		{
			name:   "Count by selectors: Invalid matcher",
			args:   []string{"-selector", "foo:bar", "-selector", "bar:baz", "-matchSelectorsOn", "NO-MATCHER"},
			expErr: "Error: match behavior \"NO-MATCHER\" unknown\n",
		},
		{
			name:   "Count by selector using invalid selector",
			args:   []string{"-selector", "invalid-selector"},
			expErr: "Error: error parsing selectors: selector \"invalid-selector\" must be formatted as type:value\n",
		},
		{
			name: "Server error",
			args: []string{"-spiffeID", "spiffe://example.org/daughter"},
			expCountReq: &entryv1.CountEntriesRequest{
				Filter: &entryv1.CountEntriesRequest_Filter{
					BySpiffeId:   &types.SPIFFEID{TrustDomain: "example.org", Path: "/daughter"},
					ByDownstream: wrapperspb.Bool(false),
				},
			},
			serverErr: status.Error(codes.Internal, "internal server error"),
			expErr:    "Error: rpc error: code = Internal desc = internal server error\n",
		},
		{
			name: "Count by Federates With: default matcher",
			args: []string{"-federatesWith", "spiffe://domain.test"},
			expCountReq: &entryv1.CountEntriesRequest{
				Filter: &entryv1.CountEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{"spiffe://domain.test"},
						Match:        types.FederatesWithMatch_MATCH_SUPERSET,
					},
					ByDownstream: wrapperspb.Bool(false),
				},
			},
			fakeCountResp: fakeResp1,
			expOutPretty:  "1 registration entry",
			expOutJSON:    `{"count":1}`,
		},
		{
			name: "Count by Federates With: exact matcher",
			args: []string{"-federatesWith", "spiffe://domain.test", "-matchFederatesWithOn", "exact"},
			expCountReq: &entryv1.CountEntriesRequest{
				Filter: &entryv1.CountEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{"spiffe://domain.test"},
						Match:        types.FederatesWithMatch_MATCH_EXACT,
					},
					ByDownstream: wrapperspb.Bool(false),
				},
			},
			fakeCountResp: fakeResp1,
			expOutPretty:  "1 registration entry",
			expOutJSON:    `{"count":1}`,
		},
		{
			name: "Count by Federates With: Any matcher",
			args: []string{"-federatesWith", "spiffe://domain.test", "-matchFederatesWithOn", "any"},
			expCountReq: &entryv1.CountEntriesRequest{
				Filter: &entryv1.CountEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{"spiffe://domain.test"},
						Match:        types.FederatesWithMatch_MATCH_ANY,
					},
					ByDownstream: wrapperspb.Bool(false),
				},
			},
			fakeCountResp: fakeResp1,
			expOutPretty:  "1 registration entry",
			expOutJSON:    `{"count":1}`,
		},
		{
			name: "Count by Federates With: superset matcher",
			args: []string{"-federatesWith", "spiffe://domain.test", "-matchFederatesWithOn", "superset"},
			expCountReq: &entryv1.CountEntriesRequest{
				Filter: &entryv1.CountEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{"spiffe://domain.test"},
						Match:        types.FederatesWithMatch_MATCH_SUPERSET,
					},
					ByDownstream: wrapperspb.Bool(false),
				},
			},
			fakeCountResp: fakeResp1,
			expOutPretty:  "1 registration entry",
			expOutJSON:    `{"count":1}`,
		},
		{
			name: "Count by Federates With: subset matcher",
			args: []string{"-federatesWith", "spiffe://domain.test", "-matchFederatesWithOn", "subset"},
			expCountReq: &entryv1.CountEntriesRequest{
				Filter: &entryv1.CountEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{"spiffe://domain.test"},
						Match:        types.FederatesWithMatch_MATCH_SUBSET,
					},
					ByDownstream: wrapperspb.Bool(false),
				},
			},
			fakeCountResp: fakeResp1,
			expOutPretty:  "1 registration entry",
			expOutJSON:    `{"count":1}`,
		},
		{
			name:   "Count by Federates With: Invalid matcher",
			args:   []string{"-federatesWith", "spiffe://domain.test", "-matchFederatesWithOn", "NO-MATCHER"},
			expErr: "Error: match behavior \"NO-MATCHER\" unknown\n",
		},
		{
			name:          "4 entries",
			fakeCountResp: fakeResp4,
			expOutPretty:  "4 registration entries\n",
			expOutJSON:    `{"count":4}`,
		},
		{
			name:          "2 entries",
			fakeCountResp: fakeResp2,
			expOutPretty:  "2 registration entries\n",
			expOutJSON:    `{"count":2}`,
		},
		{
			name:          "1 entry",
			fakeCountResp: fakeResp1,
			expOutPretty:  "1 registration entry\n",
			expOutJSON:    `{"count":1}`,
		},
		{
			name:          "0 entries",
			fakeCountResp: fakeResp0,
			expOutPretty:  "0 registration entries\n",
			expOutJSON:    `{"count":0}`,
		},
		{
			name:      "Server error",
			serverErr: status.Error(codes.Internal, "internal server error"),
			expErr:    "Error: rpc error: code = Internal desc = internal server error\n",
		},
	} {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, NewCountCommandWithEnv)
				test.server.err = tt.serverErr
				test.server.countEntriesResp = tt.fakeCountResp

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
