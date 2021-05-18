package datastore

import (
	"context"
	"time"

	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// DataStore defines the data storage interface.
type DataStore interface {
	// Bundles
	AppendBundle(context.Context, *common.Bundle) (*common.Bundle, error)
	CountBundles(context.Context) (int32, error)
	CreateBundle(context.Context, *common.Bundle) (*common.Bundle, error)
	DeleteBundle(ctx context.Context, trustDomainID string, mode DeleteMode) error
	FetchBundle(ctx context.Context, trustDomainID string) (*common.Bundle, error)
	ListBundles(context.Context, *ListBundlesRequest) (*ListBundlesResponse, error)
	PruneBundle(ctx context.Context, trustDomainID string, expiresBefore time.Time) (changed bool, err error)
	SetBundle(context.Context, *common.Bundle) (*common.Bundle, error)
	UpdateBundle(context.Context, *common.Bundle, *common.BundleMask) (*common.Bundle, error)

	// Entries
	CountRegistrationEntries(context.Context) (int32, error)
	CreateRegistrationEntry(context.Context, *common.RegistrationEntry) (*common.RegistrationEntry, error)
	DeleteRegistrationEntry(ctx context.Context, entryID string) (*common.RegistrationEntry, error)
	FetchRegistrationEntry(ctx context.Context, entryID string) (*common.RegistrationEntry, error)
	ListRegistrationEntries(context.Context, *ListRegistrationEntriesRequest) (*ListRegistrationEntriesResponse, error)
	PruneRegistrationEntries(ctx context.Context, expiresBefore time.Time) error
	UpdateRegistrationEntry(context.Context, *common.RegistrationEntry, *common.RegistrationEntryMask) (*common.RegistrationEntry, error)

	// Nodes
	CountAttestedNodes(context.Context) (int32, error)
	CreateAttestedNode(context.Context, *common.AttestedNode) (*common.AttestedNode, error)
	DeleteAttestedNode(ctx context.Context, spiffeID string) (*common.AttestedNode, error)
	FetchAttestedNode(ctx context.Context, spiffeID string) (*common.AttestedNode, error)
	ListAttestedNodes(context.Context, *ListAttestedNodesRequest) (*ListAttestedNodesResponse, error)
	UpdateAttestedNode(context.Context, *common.AttestedNode, *common.AttestedNodeMask) (*common.AttestedNode, error)

	// Node selectors
	GetNodeSelectors(context.Context, *GetNodeSelectorsRequest) (*GetNodeSelectorsResponse, error)
	ListNodeSelectors(context.Context, *ListNodeSelectorsRequest) (*ListNodeSelectorsResponse, error)
	SetNodeSelectors(context.Context, *SetNodeSelectorsRequest) (*SetNodeSelectorsResponse, error)

	// Tokens
	CreateJoinToken(context.Context, *JoinToken) error
	DeleteJoinToken(ctx context.Context, token string) error
	FetchJoinToken(ctx context.Context, token string) (*JoinToken, error)
	PruneJoinTokens(context.Context, time.Time) error
}

// DeleteMode defines delete behavior if associated records exist.
type DeleteMode int32

const (
	// Restrict the bundle from being deleted in the presence of associated entries
	Restrict DeleteMode = iota
	// Delete the bundle and associated entries
	Delete
	// Dissociate deletes the bundle and dissociates associated entries
	Dissociate
)

func (mode DeleteMode) String() string {
	switch mode {
	case Restrict:
		return "RESTRICT"
	case Delete:
		return "DELETE"
	case Dissociate:
		return "DISSOCIATE"
	default:
		return "UNKNOWN"
	}
}

type MatchBehavior int32

const (
	Exact  MatchBehavior = 0
	Subset MatchBehavior = 1
)

type ByFederatesWith struct {
	TrustDomains []string
	Match        MatchBehavior
}

type BySelectors struct {
	Selectors []*common.Selector
	Match     MatchBehavior
}

type GetNodeSelectorsRequest struct {
	SpiffeId string //nolint: golint
	// When enabled, read-only connection will be used to connect to database read instances. Some staleness of data will be observed.
	TolerateStale bool
}

type GetNodeSelectorsResponse struct {
	Selectors *NodeSelectors
}

type JoinToken struct {
	// Token value
	Token string
	// Expiration in seconds since unix epoch
	Expiry time.Time
}

type ListAttestedNodesRequest struct {
	ByExpiresBefore   *wrapperspb.Int64Value
	Pagination        *Pagination
	ByAttestationType string
	BySelectorMatch   *BySelectors
	ByBanned          *wrapperspb.BoolValue
	FetchSelectors    bool
}

type ListAttestedNodesResponse struct {
	Nodes      []*common.AttestedNode
	Pagination *Pagination
}

type ListBundlesRequest struct {
	Pagination *Pagination
}

type ListBundlesResponse struct {
	Bundles    []*common.Bundle
	Pagination *Pagination
}

type ListNodeSelectorsRequest struct {
	// When enabled, read-only connection will be used to connect to database read instances. Some staleness of data will be observed.
	TolerateStale bool
	ValidAt       *timestamppb.Timestamp
}

type ListNodeSelectorsResponse struct {
	Selectors map[string][]*common.Selector
}

type ListRegistrationEntriesRequest struct {
	ByParentId  *wrapperspb.StringValue //nolint: golint
	BySelectors *BySelectors
	BySpiffeId  *wrapperspb.StringValue //nolint: golint
	Pagination  *Pagination
	// When enabled, read-only connection will be used to connect to database read instances. Some staleness of data will be observed.
	TolerateStale   bool
	ByFederatesWith *ByFederatesWith
}

type ListRegistrationEntriesResponse struct {
	Entries    []*common.RegistrationEntry
	Pagination *Pagination
}

type NodeSelectors struct {
	// Node SPIFFE ID
	SpiffeId string //nolint: golint
	// Node selectors
	Selectors []*common.Selector
}

type Pagination struct {
	Token    string
	PageSize int32
}

type SetNodeSelectorsRequest struct {
	Selectors *NodeSelectors
}

type SetNodeSelectorsResponse struct {
}
