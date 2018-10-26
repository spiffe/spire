package sql

import (
	"time"
)

// Using our own model struct to remove DeletedAt. We don't want soft-delete support.
type Model struct {
	ID        uint `gorm:"primary_key"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Bundle struct {
	Model

	TrustDomain string `gorm:"not null;unique_index"`
	Data        []byte

	FederatedEntries []RegisteredEntry `gorm:"many2many:federated_registration_entries;"`
}

type AttestedNode struct {
	Model

	SpiffeID     string `gorm:"unique_index"`
	DataType     string
	SerialNumber string
	ExpiresAt    time.Time
}

func (AttestedNode) TableName() string {
	return "attested_node_entries"
}

type NodeSelector struct {
	Model

	SpiffeID string `gorm:"unique_index:idx_node_resolver_map"`
	Type     string `gorm:"unique_index:idx_node_resolver_map"`
	Value    string `gorm:"unique_index:idx_node_resolver_map"`
}

func (NodeSelector) TableName() string {
	return "node_resolver_map_entries"
}

type RegisteredEntry struct {
	Model

	EntryID       string `gorm:"unique_index"`
	SpiffeID      string
	ParentID      string
	TTL           int32
	Selectors     []Selector
	FederatesWith []Bundle `gorm:"many2many:federated_registration_entries;"`
}

// Keep time simple and easily comparable with UNIX time
type JoinToken struct {
	Model

	Token  string `gorm:"unique_index"`
	Expiry int64
}

type Selector struct {
	Model

	RegisteredEntryID uint   `gorm:"unique_index:idx_selector_entry"`
	Type              string `gorm:"unique_index:idx_selector_entry"`
	Value             string `gorm:"unique_index:idx_selector_entry"`
}

type Migration struct {
	Model

	// Database version
	Version int
}
