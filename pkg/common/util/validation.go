package util

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ValidateSpiffeID verifies that a Spiffe Id is valid according to SVID spec,
// for more information [https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md]
// validations done:
// - spiffe id is not empty
// - spiffe id is a valid url
// - scheme is 'spiffe'
// - host is not empty
// - host belongs to provided trust domain
// - path is not empty
// - path does not start with '/spire/' since it is reserved for agent, server, etc.
// - Fragments are not allowed
// - User info is not allowed
// - Queries are not allowed
// - Port is not allowed
func ValidateSpiffeID(spiffeID string, trustDomain url.URL) error {

	// Validate Spiffe Id is provided
	if spiffeID == "" {
		return errors.New("a SPIFFE ID is required")
	}

	// Parse Spiffe Id to url
	id, err := url.Parse(spiffeID)
	if err != nil {
		return fmt.Errorf("could not parse SPIFFE ID: %s", err.Error())
	}

	// Verify that fragments
	if id.Fragment != "" {
		return formatSpiffeIDValidationError(id.String(), "fragment is not allowed")
	}

	// Verify queries
	if id.RawQuery != "" {
		return formatSpiffeIDValidationError(id.String(), "query is not allowed")
	}

	// Verify port
	if id.Port() != "" {
		return formatSpiffeIDValidationError(id.String(), "port is not allowed")
	}

	// Verify user information
	if id.User != nil {
		return formatSpiffeIDValidationError(id.String(), "user info is not allowed")
	}

	// Verify scheme
	if id.Scheme != "spiffe" {
		return formatSpiffeIDValidationError(id.String(), "invalid scheme")
	}

	// Verify host
	if id.Host == "" {
		return formatSpiffeIDValidationError(id.String(), "host is not specified")
	}

	// Verify Path
	if id.Path == "" {
		return formatSpiffeIDValidationError(id.String(), "path is not specified")
	}

	// '/spire/' is not allowed as path, since it is reserved for agent, server, etc.
	if strings.HasPrefix(id.Path, "/spire/") {
		return formatSpiffeIDValidationError(id.String(), "invalid path")
	}

	if trustDomain.Host == "" {
		return errors.New("a trust domain is required")
	}

	// Verify that the provided spiffe id belongs to the configured trust domain
	if id.Host != trustDomain.Host {
		return fmt.Errorf("\"%s\" does not belong to configured trust domain \"%s\"", id.String(), trustDomain.Host)
	}

	return nil
}

// Return formated error to display invalid SPIFFE ID
func formatSpiffeIDValidationError(spiffeID string, err string) error {
	return fmt.Errorf("\"%s\" is not a valid SPIFFE ID: %s", spiffeID, err)
}
