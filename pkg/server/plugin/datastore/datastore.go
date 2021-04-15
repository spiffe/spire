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
	CreateBundle(context.Context, *CreateBundleRequest) (*CreateBundleResponse, error)
	DeleteBundle(context.Context, *DeleteBundleRequest) (*DeleteBundleResponse, error)
	FetchBundle(context.Context, *FetchBundleRequest) (*FetchBundleResponse, error)
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
	CreateAttestedNode(context.Context, *CreateAttestedNodeRequest) (*CreateAttestedNodeResponse, error)
	DeleteAttestedNode(context.Context, *DeleteAttestedNodeRequest) (*DeleteAttestedNodeResponse, error)
	FetchAttestedNode(context.Context, *FetchAttestedNodeRequest) (*FetchAttestedNodeResponse, error)
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

// Mode controls the delete behavior if there are other records
// associated with the bundle (e.g. registration entries).
type DeleteBundleRequest_Mode int32 //nolint: golint

const (
	// RESTRICT prevents the bundle from being deleted in the presence of associated entries
	DeleteBundleRequest_RESTRICT DeleteBundleRequest_Mode = iota //nolint: golint
	// DELETE deletes the bundle and associated entries
	DeleteBundleRequest_DELETE //nolint: golint
	// DISSOCIATE deletes the bundle and dissociates associated entries
	DeleteBundleRequest_DISSOCIATE //nolint: golint
)

func (mode DeleteBundleRequest_Mode) String() string {
	switch mode {
	case DeleteBundleRequest_RESTRICT:
		return "RESTRICT"
	case DeleteBundleRequest_DELETE:
		return "DELETE"
	case DeleteBundleRequest_DISSOCIATE:
		return "DISSOCIATE"
	default:
		return "UNKNOWN"
	}
}

type BySelectors_MatchBehavior int32 //nolint: golint

const (
	BySelectors_MATCH_EXACT  BySelectors_MatchBehavior = 0 //nolint: golint
	BySelectors_MATCH_SUBSET BySelectors_MatchBehavior = 1 //nolint: golint
)

type ByFederatesWith_MatchBehavior int32 //nolint: golint

const (
	ByFederatesWith_MATCH_EXACT  ByFederatesWith_MatchBehavior = 0 //nolint: golint
	ByFederatesWith_MATCH_SUBSET ByFederatesWith_MatchBehavior = 1 //nolint: golint
)

type AppendBundleRequest struct {
	Bundle *common.Bundle
}

type AppendBundleResponse struct {
	Bundle *common.Bundle
}

type ByFederatesWith struct {
	TrustDomains []string
	Match        ByFederatesWith_MatchBehavior
}

type BySelectors struct {
	Selectors []*common.Selector
	Match     BySelectors_MatchBehavior
}

type CreateAttestedNodeRequest struct {
	Node *common.AttestedNode
}

type CreateAttestedNodeResponse struct {
	Node *common.AttestedNode
}

type CreateBundleRequest struct {
	Bundle *common.Bundle
}

type CreateBundleResponse struct {
	Bundle *common.Bundle
}

type CreateRegistrationEntryRequest struct {
	Entry *common.RegistrationEntry
}

type CreateRegistrationEntryResponse struct {
	Entry *common.RegistrationEntry
}

type DeleteAttestedNodeRequest struct {
	SpiffeId string //nolint: golint
}

type DeleteAttestedNodeResponse struct {
	Node *common.AttestedNode
}

type DeleteBundleRequest struct {
	TrustDomainId string //nolint: golint
	Mode          DeleteBundleRequest_Mode
}

type DeleteBundleResponse struct {
	Bundle *common.Bundle
}

type DeleteRegistrationEntryRequest struct {
	EntryId string //nolint: golint
}

type DeleteRegistrationEntryResponse struct {
	Entry *common.RegistrationEntry
}

type FetchAttestedNodeRequest struct {
	SpiffeId string //nolint: golint
}

type FetchAttestedNodeResponse struct {
	Node *common.AttestedNode
}

type FetchBundleRequest struct {
	TrustDomainId string //nolint: golint
}

type FetchBundleResponse struct {
	Bundle *common.Bundle
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
