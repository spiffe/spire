package api_test

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIDFromProto(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	workload := spiffeid.RequireFromPath(td, "/workload")
	reserved := spiffeid.RequireFromPath(td, "/spire/reserved")
	agent := spiffeid.RequireFromPath(td, "/spire/agent/foo")

	type testCase struct {
		name       string
		spiffeID   *types.SPIFFEID
		expectID   spiffeid.ID
		expectErr  string
		expectLogs []spiretest.LogEntry
	}

	// These test cases are common to all of the *IDFromProto methods
	baseCases := []testCase{
		{
			name:      "no SPIFFE ID",
			expectErr: "request must specify SPIFFE ID",
		},
		{
			name:      "missing trust domain",
			spiffeID:  &types.SPIFFEID{Path: "/workload"},
			expectErr: "trust domain is missing",
		},
		{
			name:      "wrong trust domain",
			spiffeID:  &types.SPIFFEID{TrustDomain: "otherdomain.test", Path: "/workload"},
			expectErr: `"spiffe://otherdomain.test/workload" is not a member of trust domain "domain.test"`,
		},
	}

	// runTests exercises all of the test cases against the given function
	runTests := func(t *testing.T, fn func(ctx context.Context, td spiffeid.TrustDomain, protoID *types.SPIFFEID) (spiffeid.ID, error), testCases []testCase) {
		for _, testCase := range append(baseCases, testCases...) {
			testCase := testCase
			t.Run(testCase.name, func(t *testing.T) {
				log, logHook := test.NewNullLogger()

				id, err := fn(rpccontext.WithLogger(context.Background(), log), td, testCase.spiffeID)
				if testCase.expectErr != "" {
					require.EqualError(t, err, testCase.expectErr)
					return
				}
				require.NoError(t, err)
				require.Equal(t, testCase.expectID, id)

				spiretest.AssertLogs(t, logHook.AllEntries(), testCase.expectLogs)
			})
		}
	}

	t.Run("TrustDomainMemberIDFromProto", func(t *testing.T) {
		runTests(t, api.TrustDomainMemberIDFromProto, []testCase{
			{
				name:     "workload is valid member",
				spiffeID: api.ProtoFromID(workload),
				expectID: workload,
			},
			{
				name:     "reserved is valid member",
				spiffeID: api.ProtoFromID(reserved),
				expectID: reserved,
			},
			{
				name:     "agent is valid member",
				spiffeID: api.ProtoFromID(agent),
				expectID: agent,
			},
			{
				name:      "no path",
				spiffeID:  &types.SPIFFEID{TrustDomain: "domain.test"},
				expectErr: `"spiffe://domain.test" is not a member of trust domain "domain.test"; path is empty`,
			},
			{
				name:      "path without leading slash",
				spiffeID:  &types.SPIFFEID{TrustDomain: "domain.test", Path: "workload"},
				expectErr: `path must have a leading slash`,
			},
		})
	})

	t.Run("TrustDomainAgentIDFromProto", func(t *testing.T) {
		runTests(t, api.TrustDomainAgentIDFromProto, []testCase{
			{
				name:      "workload is not an agent",
				spiffeID:  api.ProtoFromID(workload),
				expectErr: `"spiffe://domain.test/workload" is not an agent in trust domain "domain.test"; path is not in the agent namespace`,
			},
			{
				name:      "reserved is not an agent",
				spiffeID:  api.ProtoFromID(reserved),
				expectErr: `"spiffe://domain.test/spire/reserved" is not an agent in trust domain "domain.test"; path is not in the agent namespace`,
			},
			{
				name:     "agent is an agent",
				spiffeID: api.ProtoFromID(agent),
				expectID: agent,
			},
			{
				name:      "no path",
				spiffeID:  &types.SPIFFEID{TrustDomain: "domain.test"},
				expectErr: `"spiffe://domain.test" is not an agent in trust domain "domain.test"; path is empty`,
			},
			{
				name:      "path without leading slash",
				spiffeID:  &types.SPIFFEID{TrustDomain: "domain.test", Path: "spire/agent/foo"},
				expectErr: `path must have a leading slash`,
			},
		})
	})

	t.Run("TrustDomainWorkloadIDFromProto", func(t *testing.T) {
		runTests(t, api.TrustDomainWorkloadIDFromProto, []testCase{
			{
				name:     "workload is a workload",
				spiffeID: api.ProtoFromID(workload),
				expectID: workload,
			},
			{
				name:      "reserved is not a workload",
				spiffeID:  api.ProtoFromID(reserved),
				expectErr: `"spiffe://domain.test/spire/reserved" is not a workload in trust domain "domain.test"; path is in the reserved namespace`,
			},
			{
				name:      "agent is not a workload",
				spiffeID:  api.ProtoFromID(agent),
				expectErr: `"spiffe://domain.test/spire/agent/foo" is not a workload in trust domain "domain.test"; path is in the reserved namespace`,
			},
			{
				name:      "no path",
				spiffeID:  &types.SPIFFEID{TrustDomain: "domain.test"},
				expectErr: `"spiffe://domain.test" is not a workload in trust domain "domain.test"; path is empty`,
			},
			{
				name:      "path without leading slash",
				spiffeID:  &types.SPIFFEID{TrustDomain: "domain.test", Path: "workload"},
				expectErr: `path must have a leading slash`,
			},
		})
	})
}

func TestVerifyTrustDomainAgentIDForNodeAttestor(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		id        spiffeid.ID
		expectErr string
	}{
		{
			name:      "not in trust domain",
			id:        spiffeid.RequireFromString("spiffe://otherdomain.test/spire/agent/foo/1234"),
			expectErr: `"spiffe://otherdomain.test/spire/agent/foo/1234" is not a member of trust domain "example.org"`,
		},
		{
			name:      "not in reserved namespace",
			id:        spiffeid.RequireFromString("spiffe://example.org/foo/1234"),
			expectErr: `"spiffe://example.org/foo/1234" is not in the agent namespace for attestor "foo"`,
		},
		{
			name:      "not in namespace for node attestor",
			id:        spiffeid.RequireFromString("spiffe://example.org/spire/agent/bar/1234"),
			expectErr: `"spiffe://example.org/spire/agent/bar/1234" is not in the agent namespace for attestor "foo"`,
		},
		{
			name: "success",
			id:   spiffeid.RequireFromString("spiffe://example.org/spire/agent/foo/1234"),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			err := api.VerifyTrustDomainAgentIDForNodeAttestor(td, testCase.id, "foo")
			if testCase.expectErr != "" {
				assert.EqualError(t, err, testCase.expectErr)
			} else {
				assert.NoError(t, err)
			}
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
			err: "node has malformed SPIFFE ID: scheme is missing or invalid",
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
