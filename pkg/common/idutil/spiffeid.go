package idutil

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
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

const (
	ServerIDPath = "/spire/server"
	AgentIDPath  = "/spire/agent"
)

// ValidateSpiffeId  performs additional validations on the SPIFFE ID object:
// - validates that the object is not empty
// - validates that the path does not start with '/spire' since it is reserved for agent, server, etc.
// - uses a validation mode to control what kind of SPIFFE ID that is expected.
func ValidateSpiffeID(id spiffeid.ID, mode ValidationMode) error {
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

	if id.IsZero() {
		return validationError("SPIFFE ID is empty")
	}

	// trust domain validation
	if options.trustDomainRequired {
		if options.trustDomain.IsZero() {
			return errors.New("trust domain to validate against cannot be empty")
		}
		if id.TrustDomain().String() != options.trustDomain.String() {
			return fmt.Errorf("%q does not belong to trust domain %q", id, options.trustDomain)
		}
	}

	// id type validation
	switch options.idType {
	case anyID:
	case trustDomainID:
		if id.Path() != "" {
			return validationError("path is not empty")
		}
	case memberID:
		if id.Path() == "" {
			return validationError("path is empty")
		}
	case workloadID:
		if id.Path() == "" {
			return validationError("path is empty")
		}
		if IsReservedPath(id.Path()) {
			return validationError(`invalid path: "/spire/*" namespace is reserved`)
		}
	case serverID:
		if id.Path() == "" {
			return validationError("path is empty")
		}
		if !isServerPath(id.Path()) {
			return validationError(`invalid path: expecting "/spire/server"`)
		}
	case agentID:
		if id.Path() == "" {
			return validationError("path is empty")
		}
		if !IsAgentPath(id.Path()) {
			return validationError(`invalid path: expecting "/spire/agent/*"`)
		}
	default:
		return validationError("internal error: unhandled id type %v", options.idType)
	}

	return nil
}

// IsAgentPath returns true if the given string is an
// SPIRE agent ID path. SPIRE agent IDs are prefixed
// with "/spire/agent/".
func IsAgentPath(path string) bool {
	return strings.HasPrefix(path, "/spire/agent/")
}

func IsReservedPath(path string) bool {
	return path == "/spire" || strings.HasPrefix(path, "/spire/")
}

func isServerPath(path string) bool {
	return path == "/spire/server"
}

// ParseSpiffeID parses the SPIFFE ID and makes sure it is valid according to
// the specified validation mode.
func ParseSpiffeID(spiffeID string, mode ValidationMode) (spiffeid.ID, error) {
	id, err := spiffeid.FromString(spiffeID)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("could not parse SPIFFE ID: %v", err)
	}

	if err := ValidateSpiffeID(id, mode); err != nil {
		return spiffeid.ID{}, err
	}

	return id, nil
}

type ValidationMode interface {
	validationOptions() validationOptions
}

type validationOptions struct {
	trustDomain         spiffeid.TrustDomain
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
func AllowAnyInTrustDomain(trustDomain spiffeid.TrustDomain) ValidationMode {
	return validationMode{
		options: validationOptions{
			trustDomain:         trustDomain,
			trustDomainRequired: true,
			idType:              memberID,
		},
	}
}

// Allows a well-formed SPIFFE ID for the specific trust domain.
func AllowTrustDomain(trustDomain spiffeid.TrustDomain) ValidationMode {
	return validationMode{
		options: validationOptions{
			trustDomain:         trustDomain,
			trustDomainRequired: true,
			idType:              trustDomainID,
		},
	}
}

// Allows a well-formed SPIFFE ID for a workload belonging to a specific trust domain.
func AllowTrustDomainWorkload(trustDomain spiffeid.TrustDomain) ValidationMode {
	return validationMode{
		options: validationOptions{
			trustDomain:         trustDomain,
			trustDomainRequired: true,
			idType:              workloadID,
		},
	}
}

func AllowTrustDomainServer(trustDomain spiffeid.TrustDomain) ValidationMode {
	return validationMode{
		options: validationOptions{
			trustDomain:         trustDomain,
			trustDomainRequired: true,
			idType:              serverID,
		},
	}
}

func AllowTrustDomainAgent(trustDomain spiffeid.TrustDomain) ValidationMode {
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

// AgentID creates an agent SPIFFE ID given a trust domain and a path.
// The /spire/agent prefix in the path is implied.
func AgentID(trustDomain spiffeid.TrustDomain, p string) spiffeid.ID {
	return trustDomain.NewID(path.Join(AgentIDPath, p))
}

// ServerID creates a server SPIFFE ID string given a trustDomain.
func ServerID(trustDomain spiffeid.TrustDomain) spiffeid.ID {
	return trustDomain.NewID(ServerIDPath)
}
