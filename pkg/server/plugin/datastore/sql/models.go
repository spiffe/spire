package sql

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
	Data        []byte `gorm:"size:16777215"` // make MySQL to use MEDIUMBLOB (max 24MB) - doesn't affect PostgreSQL/SQLite

	FederatedEntries []RegisteredEntry `gorm:"many2many:federated_registration_entries;"`
}

// AttestedNode holds an attested node (agent)
type AttestedNode struct {
	Model

	SpiffeID             string `gorm:"unique_index"`
	DataType             string
	SerialNumber         string
	ExpiresAt            time.Time
	PreparedSerialNumber string
	PreparedExpiresAt    *time.Time
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
	// TTL of identities derived from this entry
	TTL           int32
	Selectors     []Selector
	FederatesWith []Bundle `gorm:"many2many:federated_registration_entries;"`
	Admin         bool
	Downstream    bool
	// (optional) expiry of this entry
	Expiry int64 `gorm:"index"`
	// (optional) DNS entries
	DNSList []DNSName
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

// Migration holds version information
type Migration struct {
	Model

	// Database version
	Version int
}
