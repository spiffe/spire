package api_test

import (
	"testing"

	"github.com/golang/protobuf/ptypes/wrappers"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
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

func TestAttestedNodeToProto(t *testing.T) {
	testCases := []struct {
		name      string
		attNode   *common.AttestedNode
		selectors []*types.Selector
		agent     *types.Agent
		err       string
	}{
		{
			name: "success",
			attNode: &common.AttestedNode{
				SpiffeId:            "spiffe://example.org/agent",
				AttestationDataType: "attestation-type",
				CertSerialNumber:    "serial-number",
				CertNotAfter:        1,
			},
			agent: &types.Agent{
				Id:                   &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent"},
				AttestationType:      "attestation-type",
				X509SvidSerialNumber: "serial-number",
				X509SvidExpiresAt:    1,
				Banned:               false,
			},
		},
		{
			name: "invalid SPIFFE ID",
			attNode: &common.AttestedNode{
				SpiffeId: "invalid",
			},
			err: "node has malformed SPIFFE ID: spiffeid: invalid scheme",
		},
		{
			name: "missing node",
			err:  "missing node",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			agent, err := api.AttestedNodeToProto(testCase.attNode, testCase.selectors)
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}
			require.NoError(t, err)
			spiretest.AssertProtoEqual(t, testCase.agent, agent)
		})
	}
}

func TestNodeSelectorsToProto(t *testing.T) {
	testCases := []struct {
		name          string
		nodeSelectors *datastore.NodeSelectors
		selectors     []*types.Selector
		err           string
	}{
		{
			name: "success",
			nodeSelectors: &datastore.NodeSelectors{
				SpiffeId: "spiffe://example.org/agent",
				Selectors: []*common.Selector{
					{
						Type:  "type",
						Value: "value",
					},
				},
			},
			selectors: []*types.Selector{
				{
					Type:  "type",
					Value: "value",
				},
			},
		},
		{
			name: "missing node selectors",
			err:  "missing node selectors",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			selectors, err := api.NodeSelectorsToProto(testCase.nodeSelectors)
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}
			require.Equal(t, testCase.selectors, selectors)
		})
	}
}
