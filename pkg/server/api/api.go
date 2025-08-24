package api

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/nodeutil"
	"github.com/spiffe/spire/proto/spire/common"
)

// AuthorizedEntryFetcher is the interface to fetch authorized entries
type AuthorizedEntryFetcher interface {
	// LookupAuthorizedEntries fetches the entries in entryIDs that the
	// specified SPIFFE ID is authorized for
	LookupAuthorizedEntries(ctx context.Context, id spiffeid.ID, entryIDs map[string]struct{}) (map[string]ReadOnlyEntry, error)
	// FetchAuthorizedEntries fetches the entries that the specified
	// SPIFFE ID is authorized for
	FetchAuthorizedEntries(ctx context.Context, id spiffeid.ID) ([]ReadOnlyEntry, error)
}

type AttestedNodeCache interface {
	// LookupAttestedNode returns the cached attested node with the time when
	// the data was last refreshed by the cache.
	LookupAttestedNode(nodeID string) (*common.AttestedNode, time.Time)
	// FetchAttestedNode fetches, caches and returns the attested node information
	// from the datastore. Is used by the middleware when an agent can't be
	// validated against the cached data.
	FetchAttestedNode(ctx context.Context, nodeID string) (*common.AttestedNode, error)
}

// AttestedNodeToProto converts an agent from the given *common.AttestedNode with
// the provided selectors to *types.Agent
func AttestedNodeToProto(node *common.AttestedNode, selectors []*types.Selector) (*types.Agent, error) {
	if node == nil {
		return nil, errors.New("missing node")
	}

	spiffeID, err := spiffeid.FromString(node.SpiffeId)
	if err != nil {
		return nil, fmt.Errorf("node has malformed SPIFFE ID: %w", err)
	}

	return &types.Agent{
		Id:                   ProtoFromID(spiffeID),
		AttestationType:      node.AttestationDataType,
		X509SvidSerialNumber: node.CertSerialNumber,
		X509SvidExpiresAt:    node.CertNotAfter,
		Selectors:            selectors,
		Banned:               nodeutil.IsAgentBanned(node),
		CanReattest:          node.CanReattest,
	}, nil
}
