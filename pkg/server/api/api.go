package api

import (
	"context"
	"errors"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/proto/spire-next/types"
)

// IDFromProto converts a SPIFFE ID from the given types.SPIFFEID to
// spiffeid.ID
func IDFromProto(protoID *types.SPIFFEID) (spiffeid.ID, error) {
	if protoID == nil {
		return spiffeid.ID{}, errors.New("request must specify SPIFFE ID")
	}
	return spiffeid.New(protoID.TrustDomain, protoID.Path)
}

// ProtoFromID converts a SPIFFE ID from the given spiffeid.ID to
// types.SPIFFEID
func ProtoFromID(id spiffeid.ID) *types.SPIFFEID {
	return &types.SPIFFEID{
		TrustDomain: id.TrustDomain().String(),
		Path:        id.Path(),
	}
}

// AuthorizedEntryFetcher is the interface to fetch authorized entries
type AuthorizedEntryFetcher interface {
	// FetchAuthorizedEntries fetches the entries that the specified
	// SPIFFE ID is authorized for
	FetchAuthorizedEntries(ctx context.Context, id spiffeid.ID) ([]*types.Entry, error)
}

// StringValueFromSPIFFEID converts a SPIFFE ID from the given spiffeid.ID to
// *wrappers.StringValue
func StringValueFromSPIFFEID(spiffeID *types.SPIFFEID) (*wrappers.StringValue, error) {
	ID, err := IDFromProto(spiffeID)
	if err != nil {
		return nil, err
	}

	return &wrappers.StringValue{
		Value: ID.String(),
	}, nil
}
