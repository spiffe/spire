package sqlstore

import (
	"time"
)

// Model is used as a base for other models. Similar to gorm.Model without `DeletedAt`.
// We don't want soft-delete support.
type Model struct {
	ID        uint `gorm:"primary_key"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Bundle holds a trust bundle.
type Bundle struct {
	Model

	TrustDomain string `gorm:"not null;unique_index"`
	Data        []byte `gorm:"size:16777215"` // make MySQL to use MEDIUMBLOB (max 16MB) - doesn't affect PostgreSQL/SQLite

	FederatedEntries []RegisteredEntry `gorm:"many2many:federated_registration_entries;"`
}

// AttestedNode holds an attested node (agent)
type AttestedNode struct {
	Model

	SpiffeID        string `gorm:"unique_index"`
	DataType        string
	SerialNumber    string
	ExpiresAt       time.Time `gorm:"index"`
	NewSerialNumber string
	NewExpiresAt    *time.Time
	CanReattest     bool

	Selectors []*NodeSelector
}

// TableName gets table name of AttestedNode
func (AttestedNode) TableName() string {
	return "attested_node_entries"
}

type V3AttestedNode struct {
	Model

	SpiffeID     string `gorm:"unique_index"`
	DataType     string
	SerialNumber string
	ExpiresAt    time.Time
}

func (V3AttestedNode) TableName() string {
	return "attested_node_entries"
}

// NodeSelector holds a node selector by spiffe ID
type NodeSelector struct {
	Model

	SpiffeID string `gorm:"unique_index:idx_node_resolver_map"`
	Type     string `gorm:"unique_index:idx_node_resolver_map"`
	Value    string `gorm:"unique_index:idx_node_resolver_map"`
}

// TableName gets table name of NodeSelector
func (NodeSelector) TableName() string {
	return "node_resolver_map_entries"
}

// RegisteredEntry holds a registered entity entry
type RegisteredEntry struct {
	Model

	EntryID  string `gorm:"unique_index"`
	SpiffeID string `gorm:"index"`
	ParentID string `gorm:"index"`
	// TTL of identities derived from this entry. This field represents the X509-SVID TTL of the Entry
	TTL           int32
	Selectors     []Selector
	FederatesWith []Bundle `gorm:"many2many:federated_registration_entries;"`
	Admin         bool
	Downstream    bool
	// (optional) expiry of this entry
	Expiry int64 `gorm:"index"`
	// (optional) DNS entries
	DNSList []DNSName

	// RevisionNumber is a counter that is incremented when the entry is
	// updated.
	RevisionNumber int64

	// StoreSvid determines if the issued SVID is exportable to a store
	StoreSvid bool

	// Hint is a "hint string" passed to the workload to distinguish between
	// multiple SVIDs
	Hint string `gorm:"index"`

	// TTL of JWT identities derived from this entry
	JWTSvidTTL int32 `gorm:"column:jwt_svid_ttl"`
}

// JoinToken holds a join token
type JoinToken struct {
	Model

	Token  string `gorm:"unique_index"`
	Expiry int64
}

type Selector struct {
	Model

	RegisteredEntryID uint   `gorm:"unique_index:idx_selector_entry"`
	Type              string `gorm:"unique_index:idx_selector_entry;index:idx_selectors_type_value"`
	Value             string `gorm:"unique_index:idx_selector_entry;index:idx_selectors_type_value"`
}

// DNSName holds a DNS for a registration entry
type DNSName struct {
	Model

	RegisteredEntryID uint   `gorm:"unique_index:idx_dns_entry"`
	Value             string `gorm:"unique_index:idx_dns_entry"`
}

// TableName gets table name for DNS entries
func (DNSName) TableName() string {
	return "dns_names"
}

// FederatedTrustDomain holds federated trust domains.
// It has the information needed to get updated bundles of the
// federated trust domain from a SPIFFE bundle endpoint server.
type FederatedTrustDomain struct {
	Model

	// TrustDomain is the trust domain name (e.g., "example.org") to federate with.
	TrustDomain string `gorm:"not null;unique_index"`

	// BundleEndpointURL is the URL of the SPIFFE bundle endpoint that provides the trust
	// bundle to federate with.
	BundleEndpointURL string

	// BundleEndpointProfile is the endpoint profile type.
	BundleEndpointProfile string

	// EndpointSPIFFEID specifies the expected SPIFFE ID of the
	// SPIFFE bundle endpoint server when BundleEndpointProfile
	// is "https_spiffe"
	EndpointSPIFFEID string

	// Implicit indicates wether the trust domain automatically federates with
	// all registration entries by default or not.
	Implicit bool
}

// TableName gets table name of FederatedTrustDomain
func (FederatedTrustDomain) TableName() string {
	return "federated_trust_domains"
}

// Migration holds database schema version number, and
// the SPIRE Code version number
type Migration struct {
	Model

	// Database version
	Version int

	// SPIRE Code versioning
	CodeVersion string
}
