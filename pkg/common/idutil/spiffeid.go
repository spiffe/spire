package idutil

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
)

type idType int

const (
	anyID idType = iota
	trustDomainID
	memberID
	workloadID
	agentID
	serverID
)

// ValidateSpiffeID validates the SPIFFE ID according to the SPIFFE
// specification. The validation mode controls the type of validation.
func ValidateSpiffeID(spiffeID string, mode ValidationMode) error {
	_, err := ParseSpiffeID(spiffeID, mode)
	return err
}

// ValidateSpiffeIDURL validates the SPIFFE ID according to the SPIFFE
// specification, namely:
// - spiffe id is not empty
// - spiffe id is a valid url
// - scheme is 'spiffe'
// - user info is not allowed
// - host is not empty
// - port is not allowed
// - query values are not allowed
// - fragment is not allowed
// - path does not start with '/spire' since it is reserved for agent, server, etc.
// In addition, the validation mode is used to control what kind of SPIFFE ID
// is expected.
// For more information:
// [https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md]
func ValidateSpiffeIDURL(id *url.URL, mode ValidationMode) error {
	options := mode.validationOptions()

	validationError := func(format string, args ...interface{}) error {
		var kind string
		switch options.idType {
		case trustDomainID:
			kind = "trust domain "
		case memberID:
			kind = "trust domain member "
		case workloadID:
			kind = "workload "
		case serverID:
			kind = "server "
		case agentID:
			kind = "agent "
		}
		return fmt.Errorf("%q is not a valid %sSPIFFE ID: "+format,
			append([]interface{}{id.String(), kind}, args...)...)
	}

	if id == nil || *id == (url.URL{}) {
		return validationError("SPIFFE ID is empty")
	}

	// General validation
	switch {
	case strings.ToLower(id.Scheme) != "spiffe":
		return validationError("invalid scheme")
	case id.User != nil:
		return validationError("user info is not allowed")
	case id.Host == "":
		return validationError("trust domain is empty")
	case id.Port() != "":
		return validationError("port is not allowed")
	case id.Fragment != "":
		return validationError("fragment is not allowed")
	case id.RawQuery != "":
		return validationError("query is not allowed")
	}

	// trust domain validation
	if options.trustDomainRequired {
		if options.trustDomain == "" {
			return errors.New("trust domain to validate against cannot be empty")
		}
		if id.Host != options.trustDomain {
			return fmt.Errorf("%q does not belong to trust domain %q", id, options.trustDomain)
		}
	}

	// id type validation
	switch options.idType {
	case anyID:
	case trustDomainID:
		if id.Path != "" {
			return validationError("path is not empty")
		}
	case memberID:
		if id.Path == "" {
			return validationError("path is empty")
		}
	case workloadID:
		if id.Path == "" {
			return validationError("path is empty")
		}
		if isReservedPath(id.Path) {
			return validationError(`invalid path: "/spire/*" namespace is reserved`)
		}
	case serverID:
		if id.Path == "" {
			return validationError("path is empty")
		}
		if !isServerPath(id.Path) {
			return validationError(`invalid path: expecting "/spire/server"`)
		}
	case agentID:
		if id.Path == "" {
			return validationError("path is empty")
		}
		if !isAgentPath(id.Path) {
			return validationError(`invalid path: expecting "/spire/agent/*"`)
		}
	default:
		return validationError("internal error: unhandled id type %v", options.idType)
	}

	return nil
}

func isReservedPath(path string) bool {
	return path == "/spire" || strings.HasPrefix(path, "/spire/")
}

func isServerPath(path string) bool {
	return path == "/spire/server"
}

func isAgentPath(path string) bool {
	return strings.HasPrefix(path, "/spire/agent/")
}

// ParseSpiffeID parses the SPIFFE ID and makes sure it is valid according to
// the specified validation mode.
func ParseSpiffeID(spiffeID string, mode ValidationMode) (*url.URL, error) {
	u, err := url.Parse(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("could not parse SPIFFE ID: %v", err)
	}

	if err := ValidateSpiffeIDURL(u, mode); err != nil {
		return nil, err
	}

	return normalizeSpiffeIDURL(u), nil
}

type ValidationMode interface {
	validationOptions() validationOptions
}

type validationOptions struct {
	trustDomain         string
	trustDomainRequired bool
	idType              idType
}

type validationMode struct {
	options validationOptions
}

func (m validationMode) validationOptions() validationOptions {
	return m.options
}

// Allows any well-formed SPIFFE ID
func AllowAny() ValidationMode {
	return validationMode{}
}

// Allows any well-formed SPIFFE ID belonging to a specific trust domain,
// excluding the trust domain ID itself.
func AllowAnyInTrustDomain(trustDomain string) ValidationMode {
	return validationMode{
		options: validationOptions{
			trustDomain:         trustDomain,
			trustDomainRequired: true,
			idType:              memberID,
		},
	}
}

// Allows a well-formed SPIFFE ID for the specific trust domain.
func AllowTrustDomain(trustDomain string) ValidationMode {
	return validationMode{
		options: validationOptions{
			trustDomain:         trustDomain,
			trustDomainRequired: true,
			idType:              trustDomainID,
		},
	}
}

// Allows a well-formed SPIFFE ID for a workload belonging to a specific trust domain.
func AllowTrustDomainWorkload(trustDomain string) ValidationMode {
	return validationMode{
		options: validationOptions{
			trustDomain:         trustDomain,
			trustDomainRequired: true,
			idType:              workloadID,
		},
	}
}

func AllowTrustDomainServer(trustDomain string) ValidationMode {
	return validationMode{
		options: validationOptions{
			trustDomain:         trustDomain,
			trustDomainRequired: true,
			idType:              serverID,
		},
	}
}

func AllowTrustDomainAgent(trustDomain string) ValidationMode {
	return validationMode{
		options: validationOptions{
			trustDomain:         trustDomain,
			trustDomainRequired: true,
			idType:              agentID,
		},
	}
}

// Allows a well-formed SPIFFE ID for any trust domain.
func AllowAnyTrustDomain() ValidationMode {
	return validationMode{
		options: validationOptions{
			idType: trustDomainID,
		},
	}
}

// Allows a well-formed SPIFFE ID for a workload belonging to any trust domain.
func AllowAnyTrustDomainWorkload() ValidationMode {
	return validationMode{
		options: validationOptions{
			idType: workloadID,
		},
	}
}

func AllowAnyTrustDomainServer() ValidationMode {
	return validationMode{
		options: validationOptions{
			idType: serverID,
		},
	}
}

func AllowAnyTrustDomainAgent() ValidationMode {
	return validationMode{
		options: validationOptions{
			idType: agentID,
		},
	}
}

// NormalizeSpiffeID normalizes the SPIFFE ID so it can be directly compared
// for equality.
func NormalizeSpiffeID(id string, mode ValidationMode) (string, error) {
	u, err := ParseSpiffeID(id, mode)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// NormalizeSpiffeIDURL normalizes the SPIFFE ID URL so it can be directly
// compared for equality.
func NormalizeSpiffeIDURL(u *url.URL, mode ValidationMode) (*url.URL, error) {
	if err := ValidateSpiffeIDURL(u, mode); err != nil {
		return nil, err
	}
	return normalizeSpiffeIDURL(u), nil
}

func normalizeSpiffeIDURL(u *url.URL) *url.URL {
	c := *u
	c.Scheme = strings.ToLower(c.Scheme)
	// SPIFFE ID's can't contain ports so don't bother handling that here.
	c.Host = strings.ToLower(u.Hostname())
	return &c
}

// TrustDomainID creates an trust domain SPIFFE ID given a trust domain.
func TrustDomainID(trustDomain string) string {
	return TrustDomainURI(trustDomain).String()
}

// TrustDomainURI creates an trust domain SPIFFE URI given a trust domain.
func TrustDomainURI(trustDomain string) *url.URL {
	return &url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
	}
}

// AgentID creates an agent SPIFFE ID given a trust domain and a path.
// The /spire/agent prefix in the path is implied.
func AgentID(trustDomain, p string) string {
	return AgentURI(trustDomain, p).String()
}

// AgentURI creates an agent SPIFFE URI given a trust domain and a path.
// The /spire/agent prefix in the path is implied.
func AgentURI(trustDomain, p string) *url.URL {
	return &url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   path.Join("spire", "agent", p),
	}
}

// ServerID creates a server SPIFFE ID string given a trustDomain.
func ServerID(trustDomain string) string {
	return ServerURI(trustDomain).String()
}

// ServerURI creates a server SPIFFE URI given a trustDomain.
func ServerURI(trustDomain string) *url.URL {
	return &url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   path.Join("spire", "server"),
	}
}
