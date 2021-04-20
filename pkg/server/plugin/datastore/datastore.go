package datastore

import (
	"context"
	"time"

	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// DataStore is the data storage interface.
type DataStore interface {
	// Bundles
	AppendBundle(context.Context, *AppendBundleRequest) (*AppendBundleResponse, error)
	CountBundles(context.Context) (int32, error)
	CreateBundle(context.Context, *common.Bundle) (*common.Bundle, error)
	DeleteBundle(ctx context.Context, trustDomainID string, mode DeleteMode) error
	FetchBundle(ctx context.Context, trustDomainID string) (*common.Bundle, error)
	ListBundles(context.Context, *ListBundlesRequest) (*ListBundlesResponse, error)
	PruneBundle(context.Context, *PruneBundleRequest) (*PruneBundleResponse, error)
	SetBundle(context.Context, *SetBundleRequest) (*SetBundleResponse, error)
	UpdateBundle(context.Context, *UpdateBundleRequest) (*UpdateBundleResponse, error)

	// Entries
	CountRegistrationEntries(context.Context) (int32, error)
	CreateRegistrationEntry(context.Context, *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error)
	DeleteRegistrationEntry(context.Context, *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error)
	FetchRegistrationEntry(context.Context, *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error)
	ListRegistrationEntries(context.Context, *ListRegistrationEntriesRequest) (*ListRegistrationEntriesResponse, error)
	PruneRegistrationEntries(context.Context, *PruneRegistrationEntriesRequest) (*PruneRegistrationEntriesResponse, error)
	UpdateRegistrationEntry(context.Context, *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error)

	// Nodes
	CountAttestedNodes(context.Context) (int32, error)
	CreateAttestedNode(context.Context, *common.AttestedNode) (*common.AttestedNode, error)
	DeleteAttestedNode(context.Context, string) (*common.AttestedNode, error)
	FetchAttestedNode(context.Context, string) (*common.AttestedNode, error)
	ListAttestedNodes(context.Context, *ListAttestedNodesRequest) (*ListAttestedNodesResponse, error)
	UpdateAttestedNode(context.Context, *UpdateAttestedNodeRequest) (*UpdateAttestedNodeResponse, error)

	// Node selectors
	GetNodeSelectors(context.Context, *GetNodeSelectorsRequest) (*GetNodeSelectorsResponse, error)
	ListNodeSelectors(context.Context, *ListNodeSelectorsRequest) (*ListNodeSelectorsResponse, error)
	SetNodeSelectors(context.Context, *SetNodeSelectorsRequest) (*SetNodeSelectorsResponse, error)

	// Tokens
	CreateJoinToken(context.Context, *JoinToken) error
	DeleteJoinToken(context.Context, string) error
	FetchJoinToken(context.Context, string) (*JoinToken, error)
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

type AppendBundleRequest struct {
	Bundle *common.Bundle
}

type AppendBundleResponse struct {
	Bundle *common.Bundle
}

type ByFederatesWith struct {
	TrustDomains []string
	Match        MatchBehavior
}

type BySelectors struct {
	Selectors []*common.Selector
	Match     MatchBehavior
}

type CreateRegistrationEntryRequest struct {
	Entry *common.RegistrationEntry
}

type CreateRegistrationEntryResponse struct {
	Entry *common.RegistrationEntry
}

type DeleteRegistrationEntryRequest struct {
	EntryId string //nolint: golint
}

type DeleteRegistrationEntryResponse struct {
	Entry *common.RegistrationEntry
}

type FetchRegistrationEntryRequest struct {
	EntryId string //nolint: golint
}

type FetchRegistrationEntryResponse struct {
	Entry *common.RegistrationEntry
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
	Selectors []*NodeSelectors
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

type PruneBundleRequest struct {
	// Trust domain of the bundle to prune
	TrustDomainId string //nolint: golint
	// Expiration time
	ExpiresBefore int64
}
type PruneBundleResponse struct {
	BundleChanged bool
}

type PruneRegistrationEntriesRequest struct {
	ExpiresBefore int64
}

type PruneRegistrationEntriesResponse struct {
}

type SetBundleRequest struct {
	Bundle *common.Bundle
}

type SetBundleResponse struct {
	Bundle *common.Bundle
}

type SetNodeSelectorsRequest struct {
	Selectors *NodeSelectors
}

type SetNodeSelectorsResponse struct {
}

type UpdateAttestedNodeRequest struct {
	SpiffeId            string //nolint: golint
	CertSerialNumber    string
	CertNotAfter        int64
	NewCertSerialNumber string
	NewCertNotAfter     int64
	InputMask           *common.AttestedNodeMask
}

type UpdateAttestedNodeResponse struct {
	Node *common.AttestedNode
}

type UpdateBundleRequest struct {
	Bundle    *common.Bundle
	InputMask *common.BundleMask
}

type UpdateBundleResponse struct {
	Bundle *common.Bundle
}

type UpdateRegistrationEntryRequest struct {
	Entry *common.RegistrationEntry
	Mask  *common.RegistrationEntryMask
}

type UpdateRegistrationEntryResponse struct {
	Entry *common.RegistrationEntry
}
