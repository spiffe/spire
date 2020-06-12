package api_test

import (
	"context"
	"testing"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/spiffe/spire/test/fakes/fakeentryfetcher"

	"github.com/gogo/protobuf/proto"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

func TestIDFromProto(t *testing.T) {
	testCases := []struct {
		name     string
		protoID  *types.SPIFFEID
		spiffeID spiffeid.ID
		err      string
	}{
		{
			name: "valid SPIFFE ID",
			protoID: &types.SPIFFEID{
				TrustDomain: "example.test",
				Path:        "workload",
			},
			spiffeID: spiffeid.Must("example.test", "workload"),
		},
		{
			name: "no SPIFFE ID",
			err:  "request must specify SPIFFE ID",
		},
		{
			name: "missing trust domain",
			protoID: &types.SPIFFEID{
				Path: "workload",
			},
			err: "spiffeid: trust domain is empty",
		},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			spiffeID, err := api.IDFromProto(testCase.protoID)
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.spiffeID, spiffeID)
		})
	}
}

func TestFetchAuthEntries(t *testing.T) {
	ef := &fakeentryfetcher.EntryFetcher{}
	log, logHook := test.NewNullLogger()

	entry1 := types.Entry{
		Id:       "entry-1",
		ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
		SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
		Ttl:      60,
	}
	entry2 := types.Entry{
		Id:       "entry-2",
		ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
		SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/baz"},
		Ttl:      3600,
	}

	ef.Entries = []*types.Entry{proto.Clone(&entry1).(*types.Entry), proto.Clone(&entry2).(*types.Entry)}
	for _, tt := range []struct {
		name          string
		fetcherErr    string
		err           string
		expectEntries map[string]*types.Entry
		expectLogs    []spiretest.LogEntry
		failCallerID  bool
	}{
		{
			name:          "success",
			expectEntries: map[string]*types.Entry{entry1.Id: &entry1, entry2.Id: &entry2},
		},
		{
			name: "no caller id",
			err:  "rpc error: code = Internal desc = failed to fetch registration entries: missing caller ID",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to fetch registration entries",
					Data: logrus.Fields{
						logrus.ErrorKey: "missing caller ID",
					},
				},
			}, failCallerID: true,
		},
		{
			name:       "fetcher error",
			err:        "failed to fetch registration entries",
			fetcherErr: "fetcher fails",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to fetch registration entries",
					Data: logrus.Fields{
						logrus.ErrorKey: "rpc error: code = Internal desc = fetcher fails",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			logHook.Reset()
			ef.Err = tt.fetcherErr
			ctx := context.Background()
			if !tt.failCallerID {
				ctx = rpccontext.WithCallerID(ctx, spiffeid.RequireFromString("spiffe://example.org/agent"))
			}
			entriesMap, err := api.FetchAuthEntries(ctx, log, ef)

			spiretest.AssertLogs(t, logHook.AllEntries(), tt.expectLogs)
			if tt.err != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expectEntries, entriesMap)
		})
	}
}

func TestStringValueFromSPIFFEID(t *testing.T) {
	testCases := []struct {
		name     string
		protoID  *types.SPIFFEID
		expected *wrappers.StringValue
		err      string
	}{
		{
			name: "valid SPIFFE ID",
			protoID: &types.SPIFFEID{
				TrustDomain: "example.test",
				Path:        "workload",
			},
			expected: &wrappers.StringValue{
				Value: "spiffe://example.test/workload",
			},
		},
		{
			name: "invalid SPIFFE ID",
			err:  "request must specify SPIFFE ID",
		},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			stringValue, err := api.StringValueFromSPIFFEID(testCase.protoID)
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.expected, stringValue)
		})
	}
}
