package datastore

import (
	"context"
	"net/url"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	types "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/proto/spire/common"
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

	// Keys
	TaintX509CA(ctx context.Context, trustDomainID string, subjectKeyIDToTaint string) error
	RevokeX509CA(ctx context.Context, trustDomainID string, subjectKeyIDToRevoke string) error
	TaintJWTKey(ctx context.Context, trustDomainID string, authorityID string) (*common.PublicKey, error)
	RevokeJWTKey(ctx context.Context, trustDomainID string, authorityID string) (*common.PublicKey, error)

	// Entries
	CountRegistrationEntries(context.Context, *CountRegistrationEntriesRequest) (int32, error)
	CreateRegistrationEntry(context.Context, *common.RegistrationEntry) (*common.RegistrationEntry, error)
	CreateOrReturnRegistrationEntry(context.Context, *common.RegistrationEntry) (*common.RegistrationEntry, bool, error)
	DeleteRegistrationEntry(ctx context.Context, entryID string) (*common.RegistrationEntry, error)
	FetchRegistrationEntry(ctx context.Context, entryID string) (*common.RegistrationEntry, error)
	ListRegistrationEntries(context.Context, *ListRegistrationEntriesRequest) (*ListRegistrationEntriesResponse, error)
	PruneRegistrationEntries(ctx context.Context, expiresBefore time.Time) error
	UpdateRegistrationEntry(context.Context, *common.RegistrationEntry, *common.RegistrationEntryMask) (*common.RegistrationEntry, error)

	// Entries Events
	ListRegistrationEntriesEvents(ctx context.Context, req *ListRegistrationEntriesEventsRequest) (*ListRegistrationEntriesEventsResponse, error)
	PruneRegistrationEntriesEvents(ctx context.Context, olderThan time.Duration) error
	FetchRegistrationEntryEvent(ctx context.Context, eventID uint) (*RegistrationEntryEvent, error)
	CreateRegistrationEntryEventForTesting(ctx context.Context, event *RegistrationEntryEvent) error
	DeleteRegistrationEntryEventForTesting(ctx context.Context, eventID uint) error

	// Nodes
	CountAttestedNodes(context.Context, *CountAttestedNodesRequest) (int32, error)
	CreateAttestedNode(context.Context, *common.AttestedNode) (*common.AttestedNode, error)
	DeleteAttestedNode(ctx context.Context, spiffeID string) (*common.AttestedNode, error)
	FetchAttestedNode(ctx context.Context, spiffeID string) (*common.AttestedNode, error)
	ListAttestedNodes(context.Context, *ListAttestedNodesRequest) (*ListAttestedNodesResponse, error)
	UpdateAttestedNode(context.Context, *common.AttestedNode, *common.AttestedNodeMask) (*common.AttestedNode, error)

	// Nodes Events
	ListAttestedNodesEvents(ctx context.Context, req *ListAttestedNodesEventsRequest) (*ListAttestedNodesEventsResponse, error)
	PruneAttestedNodesEvents(ctx context.Context, olderThan time.Duration) error
	FetchAttestedNodeEvent(ctx context.Context, eventID uint) (*AttestedNodeEvent, error)
	CreateAttestedNodeEventForTesting(ctx context.Context, event *AttestedNodeEvent) error
	DeleteAttestedNodeEventForTesting(ctx context.Context, eventID uint) error

	// Node selectors
	GetNodeSelectors(ctx context.Context, spiffeID string, dataConsistency DataConsistency) ([]*common.Selector, error)
	ListNodeSelectors(context.Context, *ListNodeSelectorsRequest) (*ListNodeSelectorsResponse, error)
	SetNodeSelectors(ctx context.Context, spiffeID string, selectors []*common.Selector) error

	// Tokens
	CreateJoinToken(context.Context, *JoinToken) error
	DeleteJoinToken(ctx context.Context, token string) error
	FetchJoinToken(ctx context.Context, token string) (*JoinToken, error)
	PruneJoinTokens(context.Context, time.Time) error

	// Federation Relationships
	CreateFederationRelationship(context.Context, *FederationRelationship) (*FederationRelationship, error)
	FetchFederationRelationship(context.Context, spiffeid.TrustDomain) (*FederationRelationship, error)
	ListFederationRelationships(context.Context, *ListFederationRelationshipsRequest) (*ListFederationRelationshipsResponse, error)
	DeleteFederationRelationship(context.Context, spiffeid.TrustDomain) error
	UpdateFederationRelationship(context.Context, *FederationRelationship, *types.FederationRelationshipMask) (*FederationRelationship, error)

	// CA Journals
	SetCAJournal(ctx context.Context, caJournal *CAJournal) (*CAJournal, error)
	FetchCAJournal(ctx context.Context, activeX509AuthorityID string) (*CAJournal, error)
	PruneCAJournals(ctx context.Context, allCAsExpireBefore int64) error
	ListCAJournalsForTesting(ctx context.Context) ([]*CAJournal, error)
}

// DataConsistency indicates the required data consistency for a read operation.
type DataConsistency int32

const (
	// Require data from a primary database instance (default)
	RequireCurrent DataConsistency = iota

	// Allow access from available secondary database instances
	// Data staleness may be observed in the responses
	TolerateStale
)

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
	Exact    MatchBehavior = 0
	Subset   MatchBehavior = 1
	Superset MatchBehavior = 2
	MatchAny MatchBehavior = 3
)

type ByFederatesWith struct {
	TrustDomains []string
	Match        MatchBehavior
}

type BySelectors struct {
	Selectors []*common.Selector
	Match     MatchBehavior
}

type JoinToken struct {
	Token  string
	Expiry time.Time
}

type Pagination struct {
	Token    string
	PageSize int32
}

type ListAttestedNodesRequest struct {
	ByAttestationType string
	ByBanned          *bool
	ByExpiresBefore   time.Time
	BySelectorMatch   *BySelectors
	FetchSelectors    bool
	Pagination        *Pagination
	ByCanReattest     *bool
}

type ListAttestedNodesResponse struct {
	Nodes      []*common.AttestedNode
	Pagination *Pagination
}

type ListAttestedNodesEventsRequest struct {
	GreaterThanEventID uint
	LessThanEventID    uint
}

type AttestedNodeEvent struct {
	EventID  uint
	SpiffeID string
}

type ListAttestedNodesEventsResponse struct {
	Events []AttestedNodeEvent
}

type ListBundlesRequest struct {
	Pagination *Pagination
}

type ListBundlesResponse struct {
	Bundles    []*common.Bundle
	Pagination *Pagination
}

type ListNodeSelectorsRequest struct {
	DataConsistency DataConsistency
	ValidAt         time.Time
}

type ListNodeSelectorsResponse struct {
	Selectors map[string][]*common.Selector
}

type ListRegistrationEntriesRequest struct {
	DataConsistency DataConsistency
	ByParentID      string
	BySelectors     *BySelectors
	BySpiffeID      string
	Pagination      *Pagination
	ByFederatesWith *ByFederatesWith
	ByHint          string
	ByDownstream    *bool
}

type CAJournal struct {
	ID                    uint
	Data                  []byte
	ActiveX509AuthorityID string
}

type ListRegistrationEntriesResponse struct {
	Entries    []*common.RegistrationEntry
	Pagination *Pagination
}

type ListRegistrationEntriesEventsRequest struct {
	GreaterThanEventID uint
	LessThanEventID    uint
}

type RegistrationEntryEvent struct {
	EventID uint
	EntryID string
}

type ListRegistrationEntriesEventsResponse struct {
	Events []RegistrationEntryEvent
}

type ListFederationRelationshipsRequest struct {
	Pagination *Pagination
}

type ListFederationRelationshipsResponse struct {
	FederationRelationships []*FederationRelationship
	Pagination              *Pagination
}

type CountAttestedNodesRequest struct {
	ByAttestationType string
	ByBanned          *bool
	ByExpiresBefore   time.Time
	BySelectorMatch   *BySelectors
	FetchSelectors    bool
	ByCanReattest     *bool
}

type CountRegistrationEntriesRequest struct {
	DataConsistency DataConsistency
	ByParentID      string
	BySelectors     *BySelectors
	BySpiffeID      string
	ByFederatesWith *ByFederatesWith
	ByHint          string
	ByDownstream    *bool
}

type BundleEndpointType string

const (
	BundleEndpointSPIFFE BundleEndpointType = "https_spiffe"
	BundleEndpointWeb    BundleEndpointType = "https_web"
)

type FederationRelationship struct {
	TrustDomain           spiffeid.TrustDomain
	BundleEndpointURL     *url.URL
	BundleEndpointProfile BundleEndpointType
	TrustDomainBundle     *common.Bundle

	// Fields only used for 'https_spiffe' bundle endpoint profile
	EndpointSPIFFEID spiffeid.ID
}
