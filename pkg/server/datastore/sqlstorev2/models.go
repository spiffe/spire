package sqlstorev2

import (
	"time"
)

// Model is used as a base for other models. Similar to gorm.Model without
// `DeletedAt`. We don't want soft-delete support.
//
// uint columns are tagged size:31 so gorm v2 creates them as integer on
// PostgreSQL and int unsigned on MySQL, as gorm v1 did. The PostgreSQL driver
// adds a bit for unsigned types, so size:32 would produce bigint.
type Model struct {
	ID        uint `gorm:"primaryKey;size:31"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Bundle holds a trust bundle.
type Bundle struct {
	Model

	TrustDomain string `gorm:"not null;uniqueIndex:uix_bundles_trust_domain"`
	Data        []byte // longblob on MySQL, as gorm v1 created it

	FederatedEntries []RegisteredEntry `gorm:"many2many:federated_registration_entries;"`
}

// AttestedNode holds an attested node (agent)
type AttestedNode struct {
	Model

	SpiffeID        string `gorm:"uniqueIndex:uix_attested_node_entries_spiffe_id"`
	DataType        string
	SerialNumber    string
	ExpiresAt       time.Time `gorm:"index"`
	NewSerialNumber string
	NewExpiresAt    *time.Time
	CanReattest     bool
	AgentVersion    string
}

// TableName gets table name of AttestedNode
func (AttestedNode) TableName() string {
	return "attested_node_entries"
}

// AttestedNodeEvent holds the SPIFFE ID of nodes that had an event
type AttestedNodeEvent struct {
	Model

	SpiffeID string
}

// TableName gets table name for AttestedNodeEvent
func (AttestedNodeEvent) TableName() string {
	return "attested_node_entries_events"
}

// NodeSelector holds a node selector by spiffe ID
type NodeSelector struct {
	Model

	SpiffeID string `gorm:"uniqueIndex:idx_node_resolver_map"`
	Type     string `gorm:"uniqueIndex:idx_node_resolver_map"`
	Value    string `gorm:"uniqueIndex:idx_node_resolver_map"`
}

// TableName gets table name of NodeSelector
func (NodeSelector) TableName() string {
	return "node_resolver_map_entries"
}

// RegisteredEntry holds a registered entity entry
type RegisteredEntry struct {
	Model

	EntryID  string `gorm:"uniqueIndex:uix_registered_entries_entry_id"`
	SpiffeID string `gorm:"index"`
	ParentID string `gorm:"index"`
	// TTL of identities derived from this entry. X509-SVID TTL of the Entry.
	TTL           int32
	Selectors     []Selector
	FederatesWith []Bundle `gorm:"many2many:federated_registration_entries;"`
	Admin         bool
	Downstream    bool
	// (optional) expiry of this entry
	Expiry int64 `gorm:"index"`
	// (optional) DNS entries
	DNSList []DNSName

	// RevisionNumber is incremented when the entry is updated.
	RevisionNumber int64

	// StoreSvid determines if the issued SVID is exportable to a store
	StoreSvid bool

	// Hint distinguishes between multiple SVIDs
	Hint string `gorm:"index"`

	// TTL of JWT identities derived from this entry
	JWTSvidTTL int32 `gorm:"column:jwt_svid_ttl"`

	// TTL of WIT identities derived from this entry
	WITSvidTTL int32 `gorm:"column:wit_svid_ttl"`

	// AdditionalAttributes holds optional per-entry behavior controls.
	AdditionalAttributes []byte `gorm:"column:additional_attributes"`
}

// RegisteredEntryEvent holds the entry id of a registered entry that had an event
type RegisteredEntryEvent struct {
	Model

	EntryID string
}

// TableName gets table name for RegisteredEntryEvent
func (RegisteredEntryEvent) TableName() string {
	return "registered_entries_events"
}

// JoinToken holds a join token
type JoinToken struct {
	Model

	Token  string `gorm:"uniqueIndex:uix_join_tokens_token"`
	Expiry int64
}

type Selector struct {
	Model

	RegisteredEntryID uint   `gorm:"size:31;uniqueIndex:idx_selector_entry"`
	Type              string `gorm:"uniqueIndex:idx_selector_entry;index:idx_selectors_type_value"`
	Value             string `gorm:"uniqueIndex:idx_selector_entry;index:idx_selectors_type_value"`
}

// DNSName holds a DNS for a registration entry
type DNSName struct {
	Model

	RegisteredEntryID uint   `gorm:"size:31;uniqueIndex:idx_dns_entry"`
	Value             string `gorm:"uniqueIndex:idx_dns_entry"`
}

// TableName gets table name for DNS entries
func (DNSName) TableName() string {
	return "dns_names"
}

// FederatedTrustDomain holds federated trust domains.
type FederatedTrustDomain struct {
	Model

	TrustDomain string `gorm:"not null;uniqueIndex:uix_federated_trust_domains_trust_domain"`

	BundleEndpointURL string

	BundleEndpointProfile string

	EndpointSPIFFEID string

	Implicit bool
}

// TableName gets table name of FederatedTrustDomain
func (FederatedTrustDomain) TableName() string {
	return "federated_trust_domains"
}

// CAJournal holds prepared/active/old X509 and JWT authority info.
type CAJournal struct {
	Model

	// JournalID is reserved for a future externally exposed journal identifier.
	// It is not used by the current datastore implementation. It is a pointer
	// so unset values are stored as NULL, which the unique index allows more
	// than once, rather than as conflicting empty strings.
	JournalID *string `gorm:"uniqueIndex:uix_ca_journals_journal_id"`

	Data []byte // longblob on MySQL, as gorm v1 created it

	ActiveX509AuthorityID string `gorm:"index:idx_ca_journals_active_x509_authority_id"`

	ActiveJWTAuthorityID string `gorm:"index:idx_ca_journals_active_jwt_authority_id"`
}

// FederatedRegistrationEntry is the join table between registered entries and
// the bundles they federate with. It is declared explicitly so the primary
// key is (bundle_id, registered_entry_id), as gorm v1 created it. That key
// cannot serve lookups by registered_entry_id alone, so that column has its
// own index.
type FederatedRegistrationEntry struct {
	BundleID          uint `gorm:"primaryKey;autoIncrement:false;size:31"`
	RegisteredEntryID uint `gorm:"primaryKey;autoIncrement:false;size:31;index:idx_federated_registration_entries_registered_entry_id"`
}

// Migration holds database schema version number and the SPIRE code version.
type Migration struct {
	Model

	// Database version
	Version int `gorm:"size:32"`

	// SPIRE Code versioning
	CodeVersion string
}
