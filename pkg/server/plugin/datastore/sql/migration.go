package sql

import (
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/jinzhu/gorm"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

const (
	// version of the database in the code
	codeVersion = 11
)

func migrateDB(db *gorm.DB, dbType string, log hclog.Logger) (err error) {
	isNew := !db.HasTable(&Bundle{})
	if err := db.Error; err != nil {
		return sqlError.Wrap(err)
	}

	if isNew {
		return initDB(db, dbType, log)
	}

	if err := db.AutoMigrate(&Migration{}).Error; err != nil {
		return sqlError.Wrap(err)
	}

	migration := new(Migration)
	if err := db.Assign(Migration{}).FirstOrCreate(migration).Error; err != nil {
		return sqlError.Wrap(err)
	}
	version := migration.Version

	if version > codeVersion {
		err = sqlError.New("backwards migration not supported! (current=%d, code=%d)", version, codeVersion)
		log.Error(err.Error())
		return err
	}

	if version == codeVersion {
		return nil
	}

	log.Info("Running migrations...")
	for version < codeVersion {
		tx := db.Begin()
		if err := tx.Error; err != nil {
			return sqlError.Wrap(err)
		}
		version, err = migrateVersion(tx, version, log)
		if err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit().Error; err != nil {
			return sqlError.Wrap(err)
		}
	}

	log.Info("Done running migrations.")
	return nil
}

func initDB(db *gorm.DB, dbType string, log hclog.Logger) (err error) {
	log.Info("Initializing database.")
	tx := db.Begin()
	if err := tx.Error; err != nil {
		return sqlError.Wrap(err)
	}

	tables := []interface{}{
		&Bundle{},
		&AttestedNode{},
		&NodeSelector{},
		&RegisteredEntry{},
		&JoinToken{},
		&Selector{},
		&Migration{},
		&DNSName{},
	}

	if err := tableOptionsForDialect(tx, dbType).AutoMigrate(tables...).Error; err != nil {
		tx.Rollback()
		return sqlError.Wrap(err)
	}

	if err := tx.Assign(Migration{Version: codeVersion}).FirstOrCreate(&Migration{}).Error; err != nil {
		tx.Rollback()
		return sqlError.Wrap(err)
	}

	if err := addFederatedRegistrationEntriesRegisteredEntryIdIndex(tx); err != nil {
		return err
	}

	if err := tx.Commit().Error; err != nil {
		return sqlError.Wrap(err)
	}

	return nil
}

func tableOptionsForDialect(tx *gorm.DB, dbType string) *gorm.DB {
	// This allows for setting table options for a particular DB type.
	// For MySQL, (for compatibility reasons) we want to make sure that
	// we can support indexes on strings (varchar(255) in the DB).
	if dbType == MySQL {
		return tx.Set("gorm:table_options", "ENGINE=InnoDB  ROW_FORMAT=DYNAMIC DEFAULT CHARSET=utf8")
	}
	return tx
}

func migrateVersion(tx *gorm.DB, version int, log hclog.Logger) (versionOut int, err error) {
	log.Info("migrating version", telemetry.VersionInfo, version)

	// When a new version is added an entry must be included here that knows
	// how to bring the previous version up. The migrations are run
	// sequentially, each in its own transaction, to move from one version to
	// the next.
	switch version {
	case 0:
		err = migrateToV1(tx)
	case 1:
		err = migrateToV2(tx)
	case 2:
		err = migrateToV3(tx)
	case 3:
		err = migrateToV4(tx)
	case 4:
		err = migrateToV5(tx)
	case 5:
		err = migrateToV6(tx)
	case 6:
		err = migrateToV7(tx)
	case 7:
		err = migrateToV8(tx)
	case 8:
		err = migrateToV9(tx)
	case 9:
		err = migrateToV10(tx)
	case 10:
		err = migrateToV11(tx)
	default:
		err = sqlError.New("no migration support for version %d", version)
	}
	if err != nil {
		return version, err
	}

	nextVersion := version + 1
	if err := tx.Model(&Migration{}).Updates(Migration{Version: nextVersion}).Error; err != nil {
		return version, sqlError.Wrap(err)
	}

	return nextVersion, nil
}

func migrateToV1(tx *gorm.DB) error {
	v0tables := []string{
		"ca_certs",
		"bundles",
		"attested_node_entries",
		"join_tokens",
		"node_resolver_map_entries",
		"selectors",
		"registered_entries",
	}

	// soft-delete support is being removed. drop all of the records that have
	// been soft-deleted. unfortunately the "deleted_at" column cannot dropped
	// easily because that operation is not supported by all dialects (thanks,
	// sqlite3).
	for _, table := range v0tables {
		if err := tx.Exec(fmt.Sprintf("DELETE FROM %s WHERE deleted_at IS NOT NULL;", table)).Error; err != nil {
			return sqlError.Wrap(err)
		}
	}
	return nil
}

func migrateToV2(tx *gorm.DB) error {
	// creates the join table.... no changes to the tables backing these
	// models is expected. It's too bad GORM doesn't expose a way to piecemeal
	// migrate.
	if err := tx.AutoMigrate(&RegisteredEntry{}, &Bundle{}).Error; err != nil {
		return sqlError.Wrap(err)
	}

	return nil
}

func migrateToV3(tx *gorm.DB) (err error) {
	// need to normalize all of the SPIFFE IDs at rest.

	var bundles []*V3Bundle
	if err := tx.Find(&bundles).Error; err != nil {
		return sqlError.Wrap(err)
	}
	for _, bundle := range bundles {
		bundle.TrustDomain, err = idutil.NormalizeSpiffeID(bundle.TrustDomain, idutil.AllowAny())
		if err != nil {
			return sqlError.Wrap(err)
		}
		if err := tx.Save(bundle).Error; err != nil {
			return sqlError.Wrap(err)
		}
	}

	var attestedNodes []*AttestedNode
	if err := tx.Find(&attestedNodes).Error; err != nil {
		return sqlError.Wrap(err)
	}
	for _, attestedNode := range attestedNodes {
		attestedNode.SpiffeID, err = idutil.NormalizeSpiffeID(attestedNode.SpiffeID, idutil.AllowAny())
		if err != nil {
			return sqlError.Wrap(err)
		}
		if err := tx.Save(attestedNode).Error; err != nil {
			return sqlError.Wrap(err)
		}
	}

	var nodeSelectors []*NodeSelector
	if err := tx.Find(&nodeSelectors).Error; err != nil {
		return sqlError.Wrap(err)
	}
	for _, nodeSelector := range nodeSelectors {
		nodeSelector.SpiffeID, err = idutil.NormalizeSpiffeID(nodeSelector.SpiffeID, idutil.AllowAny())
		if err != nil {
			return sqlError.Wrap(err)
		}
		if err := tx.Save(nodeSelector).Error; err != nil {
			return sqlError.Wrap(err)
		}
	}

	var registeredEntries []*V4RegisteredEntry
	if err := tx.Find(&registeredEntries).Error; err != nil {
		return sqlError.Wrap(err)
	}
	for _, registeredEntry := range registeredEntries {
		registeredEntry.ParentID, err = idutil.NormalizeSpiffeID(registeredEntry.ParentID, idutil.AllowAny())
		if err != nil {
			return sqlError.Wrap(err)
		}
		registeredEntry.SpiffeID, err = idutil.NormalizeSpiffeID(registeredEntry.SpiffeID, idutil.AllowAny())
		if err != nil {
			return sqlError.Wrap(err)
		}
		if err := tx.Save(registeredEntry).Error; err != nil {
			return sqlError.Wrap(err)
		}
	}

	return nil
}

func migrateToV4(tx *gorm.DB) error {
	if err := tx.AutoMigrate(&Bundle{}).Error; err != nil {
		return sqlError.Wrap(err)
	}

	var bundleModels []*Bundle
	if err := tx.Find(&bundleModels).Error; err != nil {
		return sqlError.Wrap(err)
	}

	for _, bundleModel := range bundleModels {
		// load up all certs for the bundle
		var caCerts []V3CACert
		if err := tx.Model(bundleModel).Related(&caCerts).Error; err != nil {
			return sqlError.Wrap(err)
		}

		var derBytes []byte
		for _, caCert := range caCerts {
			derBytes = append(derBytes, caCert.Cert...)
		}

		bundle, err := bundleutil.BundleProtoFromRootCAsDER(bundleModel.TrustDomain, derBytes)
		if err != nil {
			return sqlError.Wrap(err)
		}

		data, err := proto.Marshal(bundle)
		if err != nil {
			return sqlError.Wrap(err)
		}

		bundleModel.Data = data
		if err := tx.Save(bundleModel).Error; err != nil {
			return sqlError.Wrap(err)
		}
	}

	if err := tx.Exec("DROP TABLE ca_certs").Error; err != nil {
		return sqlError.Wrap(err)
	}

	return nil
}

func migrateToV5(tx *gorm.DB) error {
	if err := tx.AutoMigrate(&V5RegisteredEntry{}).Error; err != nil {
		return sqlError.Wrap(err)
	}
	return nil
}

func migrateToV6(tx *gorm.DB) error {
	if err := tx.AutoMigrate(&V6RegisteredEntry{}).Error; err != nil {
		return sqlError.Wrap(err)
	}
	return nil
}

func migrateToV7(tx *gorm.DB) error {
	if err := tx.AutoMigrate(&V7RegisteredEntry{}).Error; err != nil {
		return sqlError.Wrap(err)
	}
	return nil
}

func migrateToV8(tx *gorm.DB) error {
	if err := tx.AutoMigrate(&V8RegisteredEntry{}, &DNSName{}).Error; err != nil {
		return sqlError.Wrap(err)
	}
	return nil
}

func migrateToV9(tx *gorm.DB) error {
	if err := tx.AutoMigrate(&V9RegisteredEntry{}, &Selector{}).Error; err != nil {
		return sqlError.Wrap(err)
	}
	return nil
}

func migrateToV10(tx *gorm.DB) error {
	if err := tx.AutoMigrate(&RegisteredEntry{}).Error; err != nil {
		return sqlError.Wrap(err)
	}
	return nil
}

func migrateToV11(tx *gorm.DB) error {
	if err := addFederatedRegistrationEntriesRegisteredEntryIdIndex(tx); err != nil {
		return err
	}
	return nil
}

func addFederatedRegistrationEntriesRegisteredEntryIdIndex(tx *gorm.DB) error {
	// GORM creates the federated_registration_entries implicitly with a primary
	// key tuple (bundle_id, registered_entry_id). Unfortunately, MySQL5 does
	// not use the primary key index efficiently when joining by registered_entry_id
	// during registration entry list operations. We can't use gorm AutoMigrate
	// to introduce the index since there is no explicit struct to add tags to
	// so we ahve to manually create it.
	if err := tx.Table("federated_registration_entries").AddIndex("idx_federated_registration_entries_registered_entry_id", "registered_entry_id").Error; err != nil {
		return sqlError.Wrap(err)
	}
	return nil
}

// V3Bundle holds a version 3 trust bundle
type V3Bundle struct {
	Model

	TrustDomain string `gorm:"not null;unique_index"`
	CACerts     []V3CACert

	FederatedEntries []RegisteredEntry `gorm:"many2many:federated_registration_entries;"`
}

// TableName get table name for v3 bundle
func (V3Bundle) TableName() string {
	return "bundles"
}

// V3CACert holds a version 3 CA certificate
type V3CACert struct {
	Model

	Cert   []byte    `gorm:"not null"`
	Expiry time.Time `gorm:"not null;index"`

	BundleID uint `gorm:"not null;index" sql:"type:integer REFERENCES bundles(id)"`
}

// TableName gets table name for v3 bundle
func (V3CACert) TableName() string {
	return "ca_certs"
}

// V4RegisteredEntry holds a version 4 registered entry
type V4RegisteredEntry struct {
	Model

	EntryID       string `gorm:"unique_index"`
	SpiffeID      string
	ParentID      string
	TTL           int32
	Selectors     []V8Selector
	FederatesWith []Bundle `gorm:"many2many:federated_registration_entries;"`
}

// TableName gets table name for v4 registered entry
func (V4RegisteredEntry) TableName() string {
	return "registered_entries"
}

// V5RegisteredEntry holds a version 5 registered entry
type V5RegisteredEntry struct {
	Model

	EntryID       string `gorm:"unique_index"`
	SpiffeID      string
	ParentID      string
	TTL           int32
	Selectors     []V8Selector
	FederatesWith []Bundle `gorm:"many2many:federated_registration_entries;"`
	Admin         bool
}

// TableName gets table name for v5 registered entry
func (V5RegisteredEntry) TableName() string {
	return "registered_entries"
}

// V6RegisteredEntry holds a version 6 registered entry
type V6RegisteredEntry struct {
	Model

	EntryID       string `gorm:"unique_index"`
	SpiffeID      string
	ParentID      string
	TTL           int32
	Selectors     []V8Selector
	FederatesWith []Bundle `gorm:"many2many:federated_registration_entries;"`
	Admin         bool
	Downstream    bool
}

// TableName gets table name for v6 registered entry
func (V6RegisteredEntry) TableName() string {
	return "registered_entries"
}

// V7RegisteredEntry holds a version 7 registered entry
type V7RegisteredEntry struct {
	Model

	EntryID  string `gorm:"unique_index"`
	SpiffeID string
	ParentID string
	// TTL of identities derived from this entry
	TTL           int32
	Selectors     []V8Selector
	FederatesWith []Bundle `gorm:"many2many:federated_registration_entries;"`
	Admin         bool
	Downstream    bool
	// (optional) expiry of this entry
	Expiry int64
}

// TableName gets table name for v7 registered entry
func (V7RegisteredEntry) TableName() string {
	return "registered_entries"
}

type V8RegisteredEntry struct {
	Model

	EntryID  string `gorm:"unique_index"`
	SpiffeID string
	ParentID string
	// TTL of identities derived from this entry
	TTL           int32
	Selectors     []V8Selector
	FederatesWith []Bundle `gorm:"many2many:federated_registration_entries;"`
	Admin         bool
	Downstream    bool
	// (optional) expiry of this entry
	Expiry int64
	// (optional) DNS entries
	DNSList []DNSName
}

// TableName gets table name for v8 registered entry
func (V8RegisteredEntry) TableName() string {
	return "registered_entries"
}

type V9RegisteredEntry struct {
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
	Expiry int64
	// (optional) DNS entries
	DNSList []DNSName
}

// TableName gets table name for v9 registered entry
func (V9RegisteredEntry) TableName() string {
	return "registered_entries"
}

type V8Selector struct {
	Model

	RegisteredEntryID uint   `gorm:"unique_index:idx_selector_entry"`
	Type              string `gorm:"unique_index:idx_selector_entry"`
	Value             string `gorm:"unique_index:idx_selector_entry"`
}
