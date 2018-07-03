package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateSpiffeIdInTrustDomain(t *testing.T) {
	tests := []struct {
		name          string
		spiffeID      string
		trustDomain   string
		expectedError string
	}{
		{
			name:          "test_validate_spiffe_id_empty_spiffe_id",
			spiffeID:      "",
			trustDomain:   "test.com",
			expectedError: "a SPIFFE ID is required",
		},
		{
			name:          "test_validate_spiffe_id_invalid_uri",
			spiffeID:      "192.168.2.2:6688",
			trustDomain:   "test.com",
			expectedError: "could not parse SPIFFE ID: parse 192.168.2.2:6688: first path segment in URL cannot contain colon",
		},
		{
			name:          "test_validate_spiffe_id_invalid_scheme",
			spiffeID:      "http://test.com/path/validate",
			trustDomain:   "test.com",
			expectedError: "\"http://test.com/path/validate\" is not a valid SPIFFE ID: invalid scheme",
		},
		{
			name:          "test_validate_spiffe_id_emtpy_host",
			spiffeID:      "spiffe:///path/validate",
			trustDomain:   "test.com",
			expectedError: "\"spiffe:///path/validate\" is not a valid SPIFFE ID: trust domain is empty",
		},
		{
			name:          "test_validate_spiffe_id_empty_path",
			spiffeID:      "spiffe://test.com",
			trustDomain:   "test.com",
			expectedError: "\"spiffe://test.com\" is not a valid SPIFFE ID: path is empty",
		},
		{
			name:          "test_validate_spiffe_id_invalid_path",
			spiffeID:      "spiffe://test.com/spire/validate",
			trustDomain:   "test.com",
			expectedError: "\"spiffe://test.com/spire/validate\" is not a valid SPIFFE ID: invalid path: \"/spire*\" namespace is restricted",
		},
		{
			name:          "test_validate_spiffe_id_empty_domain",
			spiffeID:      "spiffe://test.com/path/validate",
			trustDomain:   "",
			expectedError: "trust domain to validate against cannot be empty",
		},
		{
			name:          "test_validate_spiffe_id_domain_not_match",
			spiffeID:      "spiffe://test.com/path/validate",
			trustDomain:   "anotherdomain.com",
			expectedError: "\"spiffe://test.com/path/validate\" does not belong to trust domain \"anotherdomain.com\"",
		},
		{
			name:          "test_validate_spiffe_id_query_not_allowed",
			spiffeID:      "spiffe://test.com/path/validate?query=1",
			trustDomain:   "test.com",
			expectedError: "\"spiffe://test.com/path/validate?query=1\" is not a valid SPIFFE ID: query is not allowed",
		},
		{
			name:          "test_validate_spiffe_id_fragmentnot_allowed",
			spiffeID:      "spiffe://test.com/path/validate?#fragment-1",
			trustDomain:   "test.com",
			expectedError: "\"spiffe://test.com/path/validate?#fragment-1\" is not a valid SPIFFE ID: fragment is not allowed",
		},
		{
			name:          "test_validate_spiffe_id_port_not_allowed",
			spiffeID:      "spiffe://test.com:8080/path/validate",
			trustDomain:   "test.com",
			expectedError: "\"spiffe://test.com:8080/path/validate\" is not a valid SPIFFE ID: port is not allowed",
		},
		{
			name:          "test_validate_spiffe_id_user_info_not_allowed",
			spiffeID:      "spiffe://user:password@test.org/path/validate",
			trustDomain:   "test.com",
			expectedError: "\"spiffe://user:password@test.org/path/validate\" is not a valid SPIFFE ID: user info is not allowed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateSpiffeIDInTrustDomain(test.spiffeID, test.trustDomain)
			assert.EqualError(t, err, test.expectedError)
		})
	}

	err := ValidateSpiffeIDInTrustDomain("spiffe://test.com/path/validate", "test.com")
	assert.NoError(t, err)
}
