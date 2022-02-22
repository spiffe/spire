package idutil

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	ServerIDPath = "/spire/server"
)

func MemberFromString(td spiffeid.TrustDomain, s string) (spiffeid.ID, error) {
	id, err := spiffeid.FromString(s)
	if err != nil {
		return spiffeid.ID{}, err
	}
	if !id.MemberOf(td) {
		return spiffeid.ID{}, fmt.Errorf("SPIFFE ID %q is not a member of trust domain %q", id, td)
	}
	return id, nil
}

// IsAgentPath returns true if the given string is an
// SPIRE agent ID path. SPIRE agent IDs are prefixed
// with "/spire/agent/".
func IsAgentPath(path string) bool {
	return strings.HasPrefix(path, "/spire/agent/")
}

// IsAgentPathForNodeAttestor returns if the path lives under the agent
// namesepace for the given node attestor
func IsAgentPathForNodeAttestor(path string, nodeAttestor string) bool {
	return strings.HasPrefix(path, "/spire/agent/"+nodeAttestor+"/")
}

func IsReservedPath(path string) bool {
	return path == "/spire" || strings.HasPrefix(path, "/spire/")
}

// AgentID creates an agent SPIFFE ID given a trust domain and a path suffix.
// The path suffix must be an absolute path. The /spire/agent prefix is
// prefixed to the suffix to form the path.
func AgentID(td spiffeid.TrustDomain, suffix string) (spiffeid.ID, error) {
	if td.IsZero() {
		return spiffeid.ID{}, fmt.Errorf("cannot create agent ID with suffix %q for empty trust domain", suffix)
	}
	if err := spiffeid.ValidatePath(suffix); err != nil {
		return spiffeid.ID{}, fmt.Errorf("invalid agent path suffix %q: %w", suffix, err)
	}
	return spiffeid.FromPath(td, "/spire/agent"+suffix)
}

// ServerID creates a server SPIFFE ID string given a trust domain.
func ServerID(td spiffeid.TrustDomain) (spiffeid.ID, error) {
	if td.IsZero() {
		return spiffeid.ID{}, errors.New("cannot create server ID for empty trust domain")
	}
	return spiffeid.FromPath(td, ServerIDPath)
}
