package api

import (
	"context"
	"errors"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/proto/spire-next/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

type AuthorizedEntryFetcher interface {
	FetchAuthorizedEntries(ctx context.Context) ([]*types.Entry, error)
}

// FetchAuthEntries fetches authorized entries using caller ID from context
func FetchAuthEntries(ctx context.Context, log logrus.FieldLogger, ef AuthorizedEntryFetcher) (map[string]*types.Entry, error) {
	entries, err := ef.FetchAuthorizedEntries(ctx)
	if err != nil {
		log.WithError(err).Error("Failed to fetch registration entries")
		return nil, status.Errorf(codes.Internal, "failed to fetch registration entries: %v", err)
	}

	entriesMap := make(map[string]*types.Entry)
	for _, entry := range entries {
		entriesMap[entry.Id] = entry
	}

	return entriesMap, nil
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
