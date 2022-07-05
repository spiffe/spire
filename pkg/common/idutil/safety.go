package idutil

import (
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

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

// IDFromProto returns SPIFFE ID from the proto representation
func IDFromProto(id *types.SPIFFEID) (spiffeid.ID, error) {
	td, err := spiffeid.TrustDomainFromString(id.TrustDomain)
	if err != nil {
		return spiffeid.ID{}, err
	}
	return spiffeid.FromPath(td, id.Path)
}
