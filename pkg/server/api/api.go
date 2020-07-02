package api

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/nodeutil"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
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

// AuthorizedEntryFetcherFunc is an implementation of AuthorizedEntryFetcher
// using a function.
type AuthorizedEntryFetcherFunc func(ctx context.Context, id spiffeid.ID) ([]*types.Entry, error)

// FetchAuthorizedEntries fetches the entries that the specified
// SPIFFE ID is authorized for
func (fn AuthorizedEntryFetcherFunc) FetchAuthorizedEntries(ctx context.Context, id spiffeid.ID) ([]*types.Entry, error) {
	return fn(ctx, id)
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

// AttestedNodeToProto converts an agent from the given *common.AttestedNode with
// the provided selectors to *types.Agent
func AttestedNodeToProto(node *common.AttestedNode, selectors []*types.Selector) (*types.Agent, error) {
	if node == nil {
		return nil, errors.New("missing node")
	}

	spiffeID, err := spiffeid.FromString(node.SpiffeId)
	if err != nil {
		return nil, fmt.Errorf("node has malformed SPIFFE ID: %v", err)
	}

	return &types.Agent{
		Id:                   ProtoFromID(spiffeID),
		AttestationType:      node.AttestationDataType,
		X509SvidSerialNumber: node.CertSerialNumber,
		X509SvidExpiresAt:    node.CertNotAfter,
		Selectors:            selectors,
		Banned:               nodeutil.IsAgentBanned(node),
	}, nil
}

// NodeSelectorsToProto converts node selectors from the given
// *datastore.NodeSelectors to []*types.Selector
func NodeSelectorsToProto(nodeSelectors *datastore.NodeSelectors) ([]*types.Selector, error) {
	if nodeSelectors == nil {
		return nil, errors.New("missing node selectors")
	}

	var selectors []*types.Selector
	for _, s := range nodeSelectors.Selectors {
		selectors = append(selectors, &types.Selector{
			Type:  s.Type,
			Value: s.Value,
		})
	}

	return selectors, nil
}
