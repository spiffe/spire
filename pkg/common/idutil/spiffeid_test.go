package idutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateSpiffeID(t *testing.T) {
	tests := []struct {
		name          string
		spiffeID      string
		mode          ValidationMode
		expectedError string
	}{
		// General validation
		{
			name:          "test_validate_spiffe_id_empty_spiffe_id",
			spiffeID:      "",
			mode:          AllowAny(),
			expectedError: `"" is not a valid SPIFFE ID: SPIFFE ID is empty`,
		},
		{
			name:          "test_validate_spiffe_id_invalid_uri",
			spiffeID:      "192.168.2.2:6688",
			mode:          AllowAny(),
			expectedError: "could not parse SPIFFE ID: parse 192.168.2.2:6688: first path segment in URL cannot contain colon",
		},
		{
			name:          "test_validate_spiffe_id_invalid_scheme",
			spiffeID:      "http://test.com/path/validate",
			mode:          AllowAny(),
			expectedError: "\"http://test.com/path/validate\" is not a valid SPIFFE ID: invalid scheme",
		},
		{
			name:     "test_validate_spiffe_id_scheme_mixed_case",
			spiffeID: "SPIFFE://test.com/path/validate",
			mode:     AllowAny(),
		},
		{
			name:          "test_validate_spiffe_id_empty_host",
			spiffeID:      "spiffe:///path/validate",
			mode:          AllowAny(),
			expectedError: "\"spiffe:///path/validate\" is not a valid SPIFFE ID: trust domain is empty",
		},
		{
			name:          "test_validate_spiffe_id_query_not_allowed",
			spiffeID:      "spiffe://test.com/path/validate?query=1",
			mode:          AllowAny(),
			expectedError: "\"spiffe://test.com/path/validate?query=1\" is not a valid SPIFFE ID: query is not allowed",
		},
		{
			name:          "test_validate_spiffe_id_fragmentnot_allowed",
			spiffeID:      "spiffe://test.com/path/validate?#fragment-1",
			mode:          AllowAny(),
			expectedError: "\"spiffe://test.com/path/validate?#fragment-1\" is not a valid SPIFFE ID: fragment is not allowed",
		},
		{
			name:          "test_validate_spiffe_id_port_not_allowed",
			spiffeID:      "spiffe://test.com:8080/path/validate",
			mode:          AllowAny(),
			expectedError: "\"spiffe://test.com:8080/path/validate\" is not a valid SPIFFE ID: port is not allowed",
		},
		{
			name:          "test_validate_spiffe_id_user_info_not_allowed",
			spiffeID:      "spiffe://user:password@test.org/path/validate",
			mode:          AllowAny(),
			expectedError: "\"spiffe://user:password@test.org/path/validate\" is not a valid SPIFFE ID: user info is not allowed",
		},
		// AllowAny() mode
		{
			name:     "test_allow_any_with_trust_domain_id",
			spiffeID: "spiffe://test.com",
			mode:     AllowAny(),
		},
		{
			name:     "test_allow_any_with_trust_domain_workload_id",
			spiffeID: "spiffe://test.com/path",
			mode:     AllowAny(),
		},
		// AllowAnyInTrustDomain() mode
		{
			name:     "test_allow_any_in_trust_domain_good_with_trust_domain_id",
			spiffeID: "spiffe://test.com",
			mode:     AllowAnyInTrustDomain("test.com"),
		},
		{
			name:     "test_allow_any_in_trust_domain_good_with_workload_id",
			spiffeID: "spiffe://test.com/path",
			mode:     AllowAnyInTrustDomain("test.com"),
		},
		{
			name:     "test_allow_any_in_trust_domain_good_with_reserved_path",
			spiffeID: "spiffe://test.com/spire/foo",
			mode:     AllowAnyInTrustDomain("test.com"),
		},
		{
			name:          "test_allow_any_in_trust_domain_invalid_domain_with_trust_domain_id",
			spiffeID:      "spiffe://othertest.com",
			mode:          AllowAnyInTrustDomain("test.com"),
			expectedError: `"spiffe://othertest.com" does not belong to trust domain "test.com"`,
		},
		{
			name:          "test_allow_any_in_trust_domain_invalid_domain_with_workload_id",
			spiffeID:      "spiffe://othertest.com/path",
			mode:          AllowAnyInTrustDomain("test.com"),
			expectedError: `"spiffe://othertest.com/path" does not belong to trust domain "test.com"`,
		},

		// AllowTrustDomain() mode
		{
			name:     "test_allow_trust_domain_good",
			spiffeID: "spiffe://test.com",
			mode:     AllowTrustDomain("test.com"),
		},
		{
			name:          "test_allow_trust_domain_empty_domain_to_validate",
			spiffeID:      "spiffe://test.com",
			mode:          AllowTrustDomain(""),
			expectedError: "trust domain to validate against cannot be empty",
		},
		{
			name:          "test_allow_trust_domain_invalid",
			spiffeID:      "spiffe://othertest.com",
			mode:          AllowTrustDomain("test.com"),
			expectedError: `"spiffe://othertest.com" does not belong to trust domain "test.com"`,
		},
		{
			name:          "test_allow_trust_domain_with_a_workload",
			spiffeID:      "spiffe://test.com/path",
			mode:          AllowTrustDomain("test.com"),
			expectedError: `"spiffe://test.com/path" is not a valid trust domain SPIFFE ID: path is not empty`,
		},
		// AllowTrustDomainWorkload() mode
		{
			name:     "test_allow_trust_domain_workload_good",
			spiffeID: "spiffe://test.com/path",
			mode:     AllowTrustDomainWorkload("test.com"),
		},
		{
			name:          "test_allow_trust_domain_workload_invalid_trust_domain",
			spiffeID:      "spiffe://othertest.com/path",
			mode:          AllowTrustDomainWorkload("test.com"),
			expectedError: `"spiffe://othertest.com/path" does not belong to trust domain "test.com"`,
		},
		{
			name:          "test_allow_trust_domain_workload_missing_path",
			spiffeID:      "spiffe://test.com",
			mode:          AllowTrustDomainWorkload("test.com"),
			expectedError: `"spiffe://test.com" is not a valid workload SPIFFE ID: path is empty`,
		},
		{
			name:          "test_allow_trust_domain_workload_invalid_path",
			spiffeID:      "spiffe://test.com/spire/foo",
			mode:          AllowTrustDomainWorkload("test.com"),
			expectedError: "\"spiffe://test.com/spire/foo\" is not a valid workload SPIFFE ID: invalid path: \"/spire/*\" namespace is reserved",
		},
		// AllowAnyTrustDomain() mode
		{
			name:     "test_allow_any_trust_domain_good",
			spiffeID: "spiffe://othertest.com",
			mode:     AllowAnyTrustDomain(),
		},
		{
			name:          "test_allow_any_trust_domain_with_a_workload",
			spiffeID:      "spiffe://othertest.com/path",
			mode:          AllowAnyTrustDomain(),
			expectedError: `"spiffe://othertest.com/path" is not a valid trust domain SPIFFE ID: path is not empty`,
		},
		// AllowAnyTrustDomainWorkload() mode
		{
			name:     "test_allow_any_trust_domain_workload_good",
			spiffeID: "spiffe://othertest.com/path",
			mode:     AllowAnyTrustDomainWorkload(),
		},
		{
			name:          "test_allow_any_trust_domain_workload_missing path",
			spiffeID:      "spiffe://othertest.com",
			mode:          AllowAnyTrustDomainWorkload(),
			expectedError: `"spiffe://othertest.com" is not a valid workload SPIFFE ID: path is empty`,
		},
		{
			name:          "test_allow_any_trust_domain_workload_invalid_path",
			spiffeID:      "spiffe://othertest.com/spire/foo",
			mode:          AllowAnyTrustDomainWorkload(),
			expectedError: `"spiffe://othertest.com/spire/foo" is not a valid workload SPIFFE ID: invalid path: "/spire/*" namespace is reserved`,
		},
		// AllowTrustDomainAgent() mode
		{
			name:     "test_allow_trust_domain_agent_good",
			spiffeID: "spiffe://test.com/spire/agent/foo",
			mode:     AllowTrustDomainAgent("test.com"),
		},
		{
			name:          "test_allow_trust_domain_agent_invalid_trust_domain",
			spiffeID:      "spiffe://othertest.com/spire/agent/foo",
			mode:          AllowTrustDomainAgent("test.com"),
			expectedError: `"spiffe://othertest.com/spire/agent/foo" does not belong to trust domain "test.com"`,
		},
		{
			name:          "test_allow_trust_domain_agent_with_server",
			spiffeID:      "spiffe://test.com/spire/server",
			mode:          AllowTrustDomainAgent("test.com"),
			expectedError: `"spiffe://test.com/spire/server" is not a valid agent SPIFFE ID: invalid path: expecting "/spire/agent/*"`,
		},
		// AllowAnyTrustDomainAgent() mode
		{
			name:     "test_allow_any_trust_domain_agent_good",
			spiffeID: "spiffe://othertest.com/spire/agent/foo",
			mode:     AllowAnyTrustDomainAgent(),
		},
		{
			name:          "test_allow_any_trust_domain_agent_with_server",
			spiffeID:      "spiffe://othertest.com/spire/server",
			mode:          AllowAnyTrustDomainAgent(),
			expectedError: `"spiffe://othertest.com/spire/server" is not a valid agent SPIFFE ID: invalid path: expecting "/spire/agent/*"`,
		},
		// AllowTrustDomainServer() mode
		{
			name:     "test_allow_trust_domain_server_good",
			spiffeID: "spiffe://test.com/spire/server",
			mode:     AllowTrustDomainServer("test.com"),
		},
		{
			name:          "test_allow_trust_domain_server_invalid_trust_domain",
			spiffeID:      "spiffe://othertest.com/spire/server",
			mode:          AllowTrustDomainServer("test.com"),
			expectedError: `"spiffe://othertest.com/spire/server" does not belong to trust domain "test.com"`,
		},
		{
			name:          "test_allow_trust_domain_server_with_agent",
			spiffeID:      "spiffe://test.com/spire/agent/foo",
			mode:          AllowTrustDomainServer("test.com"),
			expectedError: `"spiffe://test.com/spire/agent/foo" is not a valid server SPIFFE ID: invalid path: expecting "/spire/server"`,
		},
		// AllowAnyTrustDomainServer() mode
		{
			name:     "test_allow_any_trust_domain_server_good",
			spiffeID: "spiffe://othertest.com/spire/server",
			mode:     AllowAnyTrustDomainServer(),
		},
		{
			name:          "test_any_allow_trust_domain_server_with_agent",
			spiffeID:      "spiffe://othertest.com/spire/agent/foo",
			mode:          AllowAnyTrustDomainServer(),
			expectedError: `"spiffe://othertest.com/spire/agent/foo" is not a valid server SPIFFE ID: invalid path: expecting "/spire/server"`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateSpiffeID(test.spiffeID, test.mode)
			if test.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.expectedError)
			}
		})
	}
}

func TestNormalizeSpiffeID(t *testing.T) {
	tests := []struct {
		name string
		in   string
		out  string
	}{
		{name: "scheme and host are lowercased", in: "SpIfFe://HoSt", out: "spiffe://host"},
		{name: "path casing is preserved", in: "SpIfFe://HoSt/PaTh", out: "spiffe://host/PaTh"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out, err := NormalizeSpiffeID(test.in)
			assert.NoError(t, err)
			assert.Equal(t, test.out, out)
		})
	}
}
