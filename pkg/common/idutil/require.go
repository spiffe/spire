package idutil

import (
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

// RequireIDProtoString constructs a SPIFFE ID string for the given ID proto.
// It panics if the proto is not well formed.
func RequireIDProtoString(id *types.SPIFFEID) string {
	out, err := IDProtoString(id)
	panicOnErr(err)
	return out
}

// RequireIDFromProto returns a SPIFFE ID from the proto representation. It
// panics if the proto is not well formed.
func RequireIDFromProto(id *types.SPIFFEID) spiffeid.ID {
	out, err := IDFromProto(id)
	panicOnErr(err)
	return out
}

// RequireServerID returns the server SPIFFE ID for the given trust domain. It
// panics if the given trust domain isn't valid.
func RequireServerID(td spiffeid.TrustDomain) spiffeid.ID {
	out, err := ServerID(td)
	panicOnErr(err)
	return out
}

// RequireAgentID creates an agent SPIFFE ID given a trust domain and a path
// suffix. The path suffix must be an absolute path. The /spire/agent prefix is
// prefixed to the suffix to form the path. It panics if the given trust domain
// isn't valid.
func RequireAgentID(td spiffeid.TrustDomain, suffix string) spiffeid.ID {
	out, err := AgentID(td, suffix)
	panicOnErr(err)
	return out
}

func panicOnErr(err error) {
	if err != nil {
		panic(err)
	}
}
