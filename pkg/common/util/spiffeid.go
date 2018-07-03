package util

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ValidateSpiffeID validates a SPIFFE ID. See ParseSpiffeID for validation
// details.
func ValidateSpiffeID(spiffeID string) error {
	_, err := ParseSpiffeID(spiffeID)
	return err
}

// ValidateSpiffeIDInTrustDomain validates the SPIFFE ID and asserts that it
// belongs to the expected trust domain. See ParseSpiffeID for validation
// details.
func ValidateSpiffeIDInTrustDomain(spiffeID, trustDomain string) error {
	if trustDomain == "" {
		return errors.New("trust domain to validate against cannot be empty")
	}

	id, err := ParseSpiffeID(spiffeID)
	if err != nil {
		return err
	}

	if id.Host != trustDomain {
		return fmt.Errorf("%q does not belong to trust domain %q", id, trustDomain)
	}

	return nil
}

// ParseSpiffeID parses and validates the SPIFFE ID according to the SPIFFE
// specification, namely:
// - spiffe id is not empty
// - spiffe id is a valid url
// - scheme is 'spiffe'
// - host is not empty
// - host belongs to provided trust domain
// - path is not empty
// - Fragments are not allowed
// - User info is not allowed
// - Queries are not allowed
// - Port is not allowed
// These additional validation steps are performed beyond those mandated by the standard:
// - path does not start with '/spire' since it is reserved for agent, server, etc.
// For more information:
// [https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md]
func ParseSpiffeID(spiffeID string) (*url.URL, error) {
	// Validate Spiffe Id is provided
	if spiffeID == "" {
		return nil, errors.New("a SPIFFE ID is required")
	}

	validationError := func(format string, args ...interface{}) error {
		return fmt.Errorf("%q is not a valid SPIFFE ID: "+format,
			append([]interface{}{spiffeID}, args...)...)
	}

	// Parse Spiffe Id to url
	id, err := url.Parse(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("could not parse SPIFFE ID: %v", err)
	}

	// Verify that fragments
	if id.Fragment != "" {
		return nil, validationError("fragment is not allowed")
	}

	// Verify queries
	if id.RawQuery != "" {
		return nil, validationError("query is not allowed")
	}

	// Verify port
	if id.Port() != "" {
		return nil, validationError("port is not allowed")
	}

	// Verify user information
	if id.User != nil {
		return nil, validationError("user info is not allowed")
	}

	// Verify scheme
	if id.Scheme != "spiffe" {
		return nil, validationError("invalid scheme")
	}

	// Verify host
	if id.Host == "" {
		return nil, validationError("trust domain is empty")
	}

	// Verify Path
	if id.Path == "" {
		return nil, validationError("path is empty")
	}

	// '/spire/' is not allowed as path, since it is reserved for agent, server, etc.
	if strings.HasPrefix(id.Path, "/spire") {
		return nil, validationError("invalid path: \"/spire*\" namespace is restricted")
	}

	return id, nil
}
