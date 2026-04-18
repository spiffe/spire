package datastore

import (
	"context"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/catalog"
	ds_types "github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
)

// DataStore defines the data storage interface. This is the interface that plugins must implement to be used as a
// datastore plugin in SPIRE server. It is based on the datastore.Datastore type defined in the `
// github.com/spiffe/spire/pkg/server/datastore` package, but it also includes the PluginInfo interface
// from the catalog package, which provides metadata about the plugin.
//
// It removes the Configure and Validate methods from the datastore.Datastore interface, as configuration and
// validation of plugins is now handled through the catalog.Plugin
// interface. The DataStore interface is intended to be used by plugin implementations, while the datastore.Datastore
// interface is intended to be used by the rest of the SPIRE server codebase to interact with the datastore plugin.
type DataStore interface {
	catalog.PluginInfo

	// Bundles
	AppendBundle(context.Context, *common.Bundle) (*common.Bundle, error)
	CountBundles(context.Context) (int32, error)
	CreateBundle(context.Context, *common.Bundle) (*common.Bundle, error)
	DeleteBundle(ctx context.Context, trustDomainID string, mode ds_types.DeleteMode) error
	FetchBundle(ctx context.Context, trustDomainID string) (*common.Bundle, error)
	ListBundles(context.Context, *ds_types.ListBundlesRequest) (*ds_types.ListBundlesResponse, error)
	PruneBundle(ctx context.Context, trustDomainID string, expiresBefore time.Time) (changed bool, err error)
	SetBundle(context.Context, *common.Bundle) (*common.Bundle, error)
	UpdateBundle(context.Context, *common.Bundle, *common.BundleMask) (*common.Bundle, error)

	// Keys
	TaintX509CA(ctx context.Context, trustDomainID string, subjectKeyIDToTaint string) error
	RevokeX509CA(ctx context.Context, trustDomainID string, subjectKeyIDToRevoke string) error
	TaintJWTKey(ctx context.Context, trustDomainID string, authorityID string) (*common.PublicKey, error)
	RevokeJWTKey(ctx context.Context, trustDomainID string, authorityID string) (*common.PublicKey, error)

	// Entries
	CountRegistrationEntries(context.Context, *ds_types.CountRegistrationEntriesRequest) (int32, error)
	CreateRegistrationEntry(context.Context, *common.RegistrationEntry) (*common.RegistrationEntry, error)
	CreateOrReturnRegistrationEntry(context.Context, *common.RegistrationEntry) (*common.RegistrationEntry, bool, error)
	DeleteRegistrationEntry(ctx context.Context, entryID string) (*common.RegistrationEntry, error)
	FetchRegistrationEntry(ctx context.Context, entryID string) (*common.RegistrationEntry, error)
	FetchRegistrationEntries(ctx context.Context, entryIDs []string) (map[string]*common.RegistrationEntry, error)
	ListRegistrationEntries(context.Context, *ds_types.ListRegistrationEntriesRequest) (*ds_types.ListRegistrationEntriesResponse, error)
	PruneRegistrationEntries(ctx context.Context, expiresBefore time.Time) error
	UpdateRegistrationEntry(context.Context, *common.RegistrationEntry, *common.RegistrationEntryMask) (*common.RegistrationEntry, error)

	// Entries Events
	ListRegistrationEntryEvents(ctx context.Context, req *ds_types.ListRegistrationEntryEventsRequest) (*ds_types.ListRegistrationEntryEventsResponse, error)
	PruneRegistrationEntryEvents(ctx context.Context, olderThan time.Duration) error
	FetchRegistrationEntryEvent(ctx context.Context, eventID uint) (*ds_types.RegistrationEntryEvent, error)
	CreateRegistrationEntryEventForTesting(ctx context.Context, event *ds_types.RegistrationEntryEvent) error
	DeleteRegistrationEntryEventForTesting(ctx context.Context, eventID uint) error

	// Nodes
	CountAttestedNodes(context.Context, *ds_types.CountAttestedNodesRequest) (int32, error)
	CreateAttestedNode(context.Context, *common.AttestedNode) (*common.AttestedNode, error)
	DeleteAttestedNode(ctx context.Context, spiffeID string) (*common.AttestedNode, error)
	FetchAttestedNode(ctx context.Context, spiffeID string) (*common.AttestedNode, error)
	ListAttestedNodes(context.Context, *ds_types.ListAttestedNodesRequest) (*ds_types.ListAttestedNodesResponse, error)
	UpdateAttestedNode(context.Context, *common.AttestedNode, *common.AttestedNodeMask) (*common.AttestedNode, error)
	PruneAttestedExpiredNodes(ctx context.Context, expiredBefore time.Time, includeNonReattestable bool) error

	// Nodes Events
	ListAttestedNodeEvents(ctx context.Context, req *ds_types.ListAttestedNodeEventsRequest) (*ds_types.ListAttestedNodeEventsResponse, error)
	PruneAttestedNodeEvents(ctx context.Context, olderThan time.Duration) error
	FetchAttestedNodeEvent(ctx context.Context, eventID uint) (*ds_types.AttestedNodeEvent, error)
	CreateAttestedNodeEventForTesting(ctx context.Context, event *ds_types.AttestedNodeEvent) error
	DeleteAttestedNodeEventForTesting(ctx context.Context, eventID uint) error

	// Node selectors
	GetNodeSelectors(ctx context.Context, spiffeID string, dataConsistency ds_types.DataConsistency) ([]*common.Selector, error)
	ListNodeSelectors(context.Context, *ds_types.ListNodeSelectorsRequest) (*ds_types.ListNodeSelectorsResponse, error)
	SetNodeSelectors(ctx context.Context, spiffeID string, selectors []*common.Selector) error

	// Tokens
	CreateJoinToken(context.Context, *ds_types.JoinToken) error
	DeleteJoinToken(ctx context.Context, token string) error
	FetchJoinToken(ctx context.Context, token string) (*ds_types.JoinToken, error)
	PruneJoinTokens(context.Context, time.Time) error

	// Federation Relationships
	CreateFederationRelationship(context.Context, *ds_types.FederationRelationship) (*ds_types.FederationRelationship, error)
	FetchFederationRelationship(context.Context, spiffeid.TrustDomain) (*ds_types.FederationRelationship, error)
	ListFederationRelationships(context.Context, *ds_types.ListFederationRelationshipsRequest) (*ds_types.ListFederationRelationshipsResponse, error)
	DeleteFederationRelationship(context.Context, spiffeid.TrustDomain) error
	UpdateFederationRelationship(context.Context, *ds_types.FederationRelationship, *types.FederationRelationshipMask) (*ds_types.FederationRelationship, error)

	// CA Journals
	SetCAJournal(ctx context.Context, caJournal *ds_types.CAJournal) (*ds_types.CAJournal, error)
	FetchCAJournal(ctx context.Context, activeX509AuthorityID string) (*ds_types.CAJournal, error)
	PruneCAJournals(ctx context.Context, allCAsExpireBefore int64) error
	ListCAJournalsForTesting(ctx context.Context) ([]*ds_types.CAJournal, error)

	Close() error
}
