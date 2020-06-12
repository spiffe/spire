package api_test

import (
	"testing"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/proto/spire-next/types"
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
