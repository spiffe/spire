package idutil

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var trustDomain = spiffeid.RequireTrustDomainFromString("test.com")

func TestValidateSpiffeID(t *testing.T) {
	testSpiffeID := spiffeid.RequireFromString("spiffe://test.com")
	testSpiffeIDPath := spiffeid.RequireFromString("spiffe://test.com/path")
	otherSpiffeID := spiffeid.RequireFromString("spiffe://othertest.com")
	otherSpiffeIDPath := spiffeid.RequireFromString("spiffe://othertest.com/path")
	reservedSpiffeID := spiffeid.RequireFromString("spiffe://test.com/spire/foo")

	tests := []struct {
		name          string
		spiffeID      spiffeid.ID
		mode          ValidationMode
		expectedError string
	}{
		// AllowAny() mode
		{
			name:     "test_allow_any_with_trust_domain_id",
			spiffeID: testSpiffeID,
			mode:     AllowAny(),
		},
		{
			name:     "test_allow_any_with_trust_domain_workload_id",
			spiffeID: testSpiffeIDPath,
			mode:     AllowAny(),
		},
		// AllowAnyInTrustDomain() mode
		{
			name:          "test_allow_any_in_trust_domain_invalid_with_trust_domain_id",
			spiffeID:      testSpiffeID,
			mode:          AllowAnyInTrustDomain(trustDomain),
			expectedError: `"spiffe://test.com" is not a valid trust domain member SPIFFE ID: path is empty`,
		},
		{
			name:     "test_allow_any_in_trust_domain_good_with_workload_id",
			spiffeID: testSpiffeIDPath,
			mode:     AllowAnyInTrustDomain(trustDomain),
		},
		{
			name:     "test_allow_any_in_trust_domain_good_with_reserved_path",
			spiffeID: reservedSpiffeID,
			mode:     AllowAnyInTrustDomain(trustDomain),
		},
		{
			name:          "test_allow_any_in_trust_domain_invalid_domain_with_trust_domain_id",
			spiffeID:      otherSpiffeID,
			mode:          AllowAnyInTrustDomain(trustDomain),
			expectedError: `"spiffe://othertest.com" does not belong to trust domain "test.com"`,
		},
		{
			name:          "test_allow_any_in_trust_domain_invalid_domain_with_workload_id",
			spiffeID:      otherSpiffeIDPath,
			mode:          AllowAnyInTrustDomain(trustDomain),
			expectedError: `"spiffe://othertest.com/path" does not belong to trust domain "test.com"`,
		},

		// AllowTrustDomain() mode
		{
			name:     "test_allow_trust_domain_good",
			spiffeID: testSpiffeID,
			mode:     AllowTrustDomain(trustDomain),
		},
		{
			name:          "test_allow_trust_domain_empty_domain_to_validate",
			spiffeID:      testSpiffeID,
			mode:          AllowTrustDomain(spiffeid.TrustDomain{}),
			expectedError: "trust domain to validate against cannot be empty",
		},
		{
			name:          "test_allow_trust_domain_invalid",
			spiffeID:      otherSpiffeID,
			mode:          AllowTrustDomain(trustDomain),
			expectedError: `"spiffe://othertest.com" does not belong to trust domain "test.com"`,
		},
		{
			name:          "test_allow_trust_domain_with_a_workload",
			spiffeID:      testSpiffeIDPath,
			mode:          AllowTrustDomain(trustDomain),
			expectedError: `"spiffe://test.com/path" is not a valid trust domain SPIFFE ID: path is not empty`,
		},
		// AllowTrustDomainWorkload() mode
		{
			name:     "test_allow_trust_domain_workload_good",
			spiffeID: testSpiffeIDPath,
			mode:     AllowTrustDomainWorkload(trustDomain),
		},
		{
			name:          "test_allow_trust_domain_workload_invalid_trust_domain",
			spiffeID:      otherSpiffeIDPath,
			mode:          AllowTrustDomainWorkload(trustDomain),
			expectedError: `"spiffe://othertest.com/path" does not belong to trust domain "test.com"`,
		},
		{
			name:          "test_allow_trust_domain_workload_missing_path",
			spiffeID:      testSpiffeID,
			mode:          AllowTrustDomainWorkload(trustDomain),
			expectedError: `"spiffe://test.com" is not a valid workload SPIFFE ID: path is empty`,
		},
		{
			name:          "test_allow_trust_domain_workload_invalid_path",
			spiffeID:      reservedSpiffeID,
			mode:          AllowTrustDomainWorkload(trustDomain),
			expectedError: "\"spiffe://test.com/spire/foo\" is not a valid workload SPIFFE ID: invalid path: \"/spire/*\" namespace is reserved",
		},
		// AllowAnyTrustDomain() mode
		{
			name:     "test_allow_any_trust_domain_good",
			spiffeID: otherSpiffeID,
			mode:     AllowAnyTrustDomain(),
		},
		{
			name:          "test_allow_any_trust_domain_with_a_workload",
			spiffeID:      otherSpiffeIDPath,
			mode:          AllowAnyTrustDomain(),
			expectedError: `"spiffe://othertest.com/path" is not a valid trust domain SPIFFE ID: path is not empty`,
		},
		// AllowAnyTrustDomainWorkload() mode
		{
			name:     "test_allow_any_trust_domain_workload_good",
			spiffeID: otherSpiffeIDPath,
			mode:     AllowAnyTrustDomainWorkload(),
		},
		{
			name:          "test_allow_any_trust_domain_workload_missing path",
			spiffeID:      otherSpiffeID,
			mode:          AllowAnyTrustDomainWorkload(),
			expectedError: `"spiffe://othertest.com" is not a valid workload SPIFFE ID: path is empty`,
		},
		{
			name:          "test_allow_any_trust_domain_workload_invalid_path",
			spiffeID:      spiffeid.RequireFromString("spiffe://othertest.com/spire/foo"),
			mode:          AllowAnyTrustDomainWorkload(),
			expectedError: `"spiffe://othertest.com/spire/foo" is not a valid workload SPIFFE ID: invalid path: "/spire/*" namespace is reserved`,
		},
		// AllowTrustDomainAgent() mode
		{
			name:     "test_allow_trust_domain_agent_good",
			spiffeID: spiffeid.RequireFromString("spiffe://test.com/spire/agent/foo"),
			mode:     AllowTrustDomainAgent(trustDomain),
		},
		{
			name:          "test_allow_trust_domain_agent_invalid_trust_domain",
			spiffeID:      spiffeid.RequireFromString("spiffe://othertest.com/spire/agent/foo"),
			mode:          AllowTrustDomainAgent(trustDomain),
			expectedError: `"spiffe://othertest.com/spire/agent/foo" does not belong to trust domain "test.com"`,
		},
		{
			name:          "test_allow_trust_domain_agent_with_server",
			spiffeID:      spiffeid.RequireFromString("spiffe://test.com/spire/server"),
			mode:          AllowTrustDomainAgent(trustDomain),
			expectedError: `"spiffe://test.com/spire/server" is not a valid agent SPIFFE ID: invalid path: expecting "/spire/agent/*"`,
		},
		// AllowAnyTrustDomainAgent() mode
		{
			name:     "test_allow_any_trust_domain_agent_good",
			spiffeID: spiffeid.RequireFromString("spiffe://othertest.com/spire/agent/foo"),
			mode:     AllowAnyTrustDomainAgent(),
		},
		{
			name:          "test_allow_any_trust_domain_agent_with_server",
			spiffeID:      spiffeid.RequireFromString("spiffe://othertest.com/spire/server"),
			mode:          AllowAnyTrustDomainAgent(),
			expectedError: `"spiffe://othertest.com/spire/server" is not a valid agent SPIFFE ID: invalid path: expecting "/spire/agent/*"`,
		},
		// AllowTrustDomainServer() mode
		{
			name:     "test_allow_trust_domain_server_good",
			spiffeID: spiffeid.RequireFromString("spiffe://test.com/spire/server"),
			mode:     AllowTrustDomainServer(trustDomain),
		},
		{
			name:          "test_allow_trust_domain_server_invalid_trust_domain",
			spiffeID:      spiffeid.RequireFromString("spiffe://othertest.com/spire/server"),
			mode:          AllowTrustDomainServer(trustDomain),
			expectedError: `"spiffe://othertest.com/spire/server" does not belong to trust domain "test.com"`,
		},
		{
			name:          "test_allow_trust_domain_server_with_agent",
			spiffeID:      spiffeid.RequireFromString("spiffe://test.com/spire/agent/foo"),
			mode:          AllowTrustDomainServer(trustDomain),
			expectedError: `"spiffe://test.com/spire/agent/foo" is not a valid server SPIFFE ID: invalid path: expecting "/spire/server"`,
		},
		// AllowAnyTrustDomainServer() mode
		{
			name:     "test_allow_any_trust_domain_server_good",
			spiffeID: spiffeid.RequireFromString("spiffe://othertest.com/spire/server"),
			mode:     AllowAnyTrustDomainServer(),
		},
		{
			name:          "test_any_allow_trust_domain_server_with_agent",
			spiffeID:      spiffeid.RequireFromString("spiffe://othertest.com/spire/agent/foo"),
			mode:          AllowAnyTrustDomainServer(),
			expectedError: `"spiffe://othertest.com/spire/agent/foo" is not a valid server SPIFFE ID: invalid path: expecting "/spire/server"`,
		},
	}

	for _, test := range tests {
		test := test // alias loop variable as it is used in the closure
		t.Run(test.name, func(t *testing.T) {
			err := ValidateSpiffeID(test.spiffeID, test.mode)
			if test.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.expectedError)
			}
		})
	}
}

func TestIsAgentPath(t *testing.T) {
	require.False(t, IsAgentPath(""))
	require.False(t, IsAgentPath("/not/an/agent/path"))
	require.True(t, IsAgentPath("/spire/agent/join_token/d3f678b4-d41d-4b1c-a971-73e012729b43"))
}
