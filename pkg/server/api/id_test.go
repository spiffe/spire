package api_test

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

func TestIDFromProto(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	workload := td.NewID("/workload")
	reserved := td.NewID("/spire/reserved")
	agent := td.NewID("/spire/agent/foo")

	type testCase struct {
		name        string
		spiffeID    *types.SPIFFEID
		expectedID  spiffeid.ID
		expectedErr string
	}

	// These test cases are common to all of the *IDFromProto methods
	baseCases := []testCase{
		{
			name:        "no SPIFFE ID",
			expectedErr: "request must specify SPIFFE ID",
		},
		{
			name:        "missing trust domain",
			spiffeID:    &types.SPIFFEID{Path: "/workload"},
			expectedErr: "trust domain is empty",
		},
		{
			name:        "wrong trust domain",
			spiffeID:    &types.SPIFFEID{TrustDomain: "otherdomain.test", Path: "/workload"},
			expectedErr: `"spiffe://otherdomain.test/workload" is not a member of trust domain "domain.test"`,
		},
	}

	// runTests exercises all of the test cases against the given function
	runTests := func(t *testing.T, fn func(td spiffeid.TrustDomain, protoID *types.SPIFFEID) (spiffeid.ID, error), testCases []testCase) {
		for _, testCase := range append(baseCases, testCases...) {
			testCase := testCase
			t.Run(testCase.name, func(t *testing.T) {
				id, err := fn(td, testCase.spiffeID)
				if testCase.expectedErr != "" {
					require.EqualError(t, err, testCase.expectedErr)
					return
				}
				require.NoError(t, err)
				require.Equal(t, testCase.expectedID, id)
			})
		}
	}

	t.Run("TrustDomainMemberIDFromProto", func(t *testing.T) {
		runTests(t, api.TrustDomainMemberIDFromProto, []testCase{
			{
				name:       "workload is valid member",
				spiffeID:   api.ProtoFromID(workload),
				expectedID: workload,
			},
			{
				name:       "reserved is valid member",
				spiffeID:   api.ProtoFromID(reserved),
				expectedID: reserved,
			},
			{
				name:       "agent is valid member",
				spiffeID:   api.ProtoFromID(agent),
				expectedID: agent,
			},
			{
				name:        "no path",
				spiffeID:    &types.SPIFFEID{TrustDomain: "domain.test"},
				expectedErr: `"spiffe://domain.test" is not a member of trust domain "domain.test"; path is empty`,
			},
		})
	})

	t.Run("TrustDomainAgentIDFromProto", func(t *testing.T) {
		runTests(t, api.TrustDomainAgentIDFromProto, []testCase{
			{
				name:        "workload is not an agent",
				spiffeID:    api.ProtoFromID(workload),
				expectedErr: `"spiffe://domain.test/workload" is not an agent in trust domain "domain.test"; path is not in the agent namespace`,
			},
			{
				name:        "reserved is not an agent",
				spiffeID:    api.ProtoFromID(reserved),
				expectedErr: `"spiffe://domain.test/spire/reserved" is not an agent in trust domain "domain.test"; path is not in the agent namespace`,
			},
			{
				name:       "agent is an agent",
				spiffeID:   api.ProtoFromID(agent),
				expectedID: agent,
			},
			{
				name:        "no path",
				spiffeID:    &types.SPIFFEID{TrustDomain: "domain.test"},
				expectedErr: `"spiffe://domain.test" is not an agent in trust domain "domain.test"; path is empty`,
			},
		})
	})

	t.Run("TrustDomainWorkloadIDFromProto", func(t *testing.T) {
		runTests(t, api.TrustDomainWorkloadIDFromProto, []testCase{
			{
				name:       "workload is a workload",
				spiffeID:   api.ProtoFromID(workload),
				expectedID: workload,
			},
			{
				name:        "reserved is not a workload",
				spiffeID:    api.ProtoFromID(reserved),
				expectedErr: `"spiffe://domain.test/spire/reserved" is not a workload in trust domain "domain.test"; path is in the reserved namespace`,
			},
			{
				name:        "agent is not a workload",
				spiffeID:    api.ProtoFromID(agent),
				expectedErr: `"spiffe://domain.test/spire/agent/foo" is not a workload in trust domain "domain.test"; path is in the reserved namespace`,
			},
			{
				name:        "no path",
				spiffeID:    &types.SPIFFEID{TrustDomain: "domain.test"},
				expectedErr: `"spiffe://domain.test" is not a workload in trust domain "domain.test"; path is empty`,
			},
		})
	})
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
