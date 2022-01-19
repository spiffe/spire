package idutil

import (
	"errors"
	"net/url"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

// CheckIDProtoNormalization ensures the the provided ID is properly normalized.
func CheckIDProtoNormalization(in *types.SPIFFEID) error {
	_, err := IDProtoString(in)
	return err
}

// CheckIDStringNormalization ensures the the provided ID is properly normalized.
func CheckIDStringNormalization(id string) error {
	_, err := spiffeid.FromString(id)
	return err
}

// CheckIDURLNormalization returns if a URL is normalized or not. It relies on
// behavior and fields populated by url.Parse(). DO NOT call it with a URL that
// has not gone through url.Parse().
func CheckIDURLNormalization(u *url.URL) error {
	return CheckIDStringNormalization(u.String())
}

// IDProtoString constructs a SPIFFE ID string for the given ID protobuf.
func IDProtoString(id *types.SPIFFEID) (string, error) {
	out, err := IDFromProto(id)
	if err != nil {
		return "", err
	}
	return out.String(), nil
}

// IDProtoFromString parses a SPIFFE ID string into the raw ID proto components.
// It does not attempt to escape/unescape any portion of the ID.
func IDProtoFromString(s string) (*types.SPIFFEID, error) {
	id, err := spiffeid.FromString(s)
	if err != nil {
		return nil, err
	}
	return &types.SPIFFEID{
		TrustDomain: id.TrustDomain().String(),
		Path:        id.Path(),
	}, nil
}

// CheckAgentIDStringNormalization ensures the provided agent ID string is
// properly normalized. It also ensures it is not a server ID.
func CheckAgentIDStringNormalization(agentID string) error {
	id, err := spiffeid.FromString(agentID)
	if err != nil {
		return err
	}

	// We want to do more than this but backcompat compels us to not too. We'll
	// get more aggressive in the future.
	if id.Path() == ServerIDPath {
		return errors.New("server ID is not allowed for agents")
	}

	return nil
}

// IDFromProto returns SPIFFE ID from the proto representation
func IDFromProto(id *types.SPIFFEID) (spiffeid.ID, error) {
	td, err := spiffeid.TrustDomainFromString(id.TrustDomain)
	if err != nil {
		return spiffeid.ID{}, err
	}
	return spiffeid.FromPath(td, id.Path)
}

// EnsureLeadingSlashForBackcompat is for backcompat only. It adds a leading
// slash to a path, if necessary. It is not expected to receive more callers.
// Deprecated: remove in SPIRE 1.3
func EnsureLeadingSlashForBackcompat(path string) (string, bool) {
	if len(path) != 0 && path[0] != '/' {
		return "/" + path, true
	}
	return path, false
}
