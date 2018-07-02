package sql

import (
	"time"

	"github.com/jinzhu/gorm"
)

type Bundle struct {
	gorm.Model

	TrustDomain string `gorm:"not null;unique_index"`
	CACerts     []CACert
}

type CACert struct {
	gorm.Model

	Cert   []byte    `gorm:"size:4095;not null"`
	Expiry time.Time `gorm:"not null;default:CURRENT_TIMESTAMP;index"`

	BundleID uint `gorm:"index" sql:"NOT NULL, FOREIGN KEY (bundle_id) REFERENCES bundles(id)"`
}

type AttestedNodeEntry struct {
	gorm.Model

	SpiffeID     string `gorm:"unique_index"`
	DataType     string
	SerialNumber string
	ExpiresAt    time.Time
}

type NodeResolverMapEntry struct {
	gorm.Model

	SpiffeID string `gorm:"unique_index:idx_node_resolver_map"`
	Type     string `gorm:"unique_index:idx_node_resolver_map"`
	Value    string `gorm:"unique_index:idx_node_resolver_map"`
}

type RegisteredEntry struct {
	gorm.Model

	EntryID   string `gorm:"unique_index"`
	SpiffeID  string
	ParentID  string
	TTL       int32
	Selectors []Selector
	// TODO: Add support to Federated Bundles [https://github.com/spiffe/spire/issues/42]
}

// Keep time simple and easily comparable with UNIX time
type JoinToken struct {
	gorm.Model

	Token  string `gorm:"unique_index"`
	Expiry int64
}

type Selector struct {
	gorm.Model

	RegisteredEntryID uint   `gorm:"unique_index:idx_selector_entry"`
	Type              string `gorm:"unique_index:idx_selector_entry"`
	Value             string `gorm:"unique_index:idx_selector_entry"`
}

func migrateDB(db *gorm.DB) {
	db.AutoMigrate(&Bundle{}, &CACert{}, &AttestedNodeEntry{},
		&NodeResolverMapEntry{}, &RegisteredEntry{}, &JoinToken{},
		&Selector{})
	return
}
