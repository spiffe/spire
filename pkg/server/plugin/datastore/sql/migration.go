package sql

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/blang/semver"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/jinzhu/gorm"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/version"
	"google.golang.org/protobuf/proto"
)

const (
	// the latest schema version of the database in the code
	latestSchemaVersion = 15
)

var (
	// the current code version
	codeVersion = semver.MustParse(version.Version())
)

func migrateDB(db *gorm.DB, dbType string, disableMigration bool, log hclog.Logger) (err error) {
	// The version comparison logic in this package supports only 0.x and 1.x versioning semantics.
	// It will need to be updated prior to releasing 2.x. Ensure that we're still building a pre-2.0
	// version before continuing, and fail if we're not.
	if codeVersion.Major > 1 {
		log.Error("Migration code needs updating for current release version")
		return sqlError.New("current migration code not compatible with current release version")
	}

	isNew := !db.HasTable(&Bundle{})
	if err := db.Error; err != nil {
		return sqlError.Wrap(err)
	}

	if isNew {
		return initDB(db, dbType, log)
	}

	// ensure migrations table exists so we can check versioning in all cases
	if err := db.AutoMigrate(&Migration{}).Error; err != nil {
		return sqlError.Wrap(err)
	}

	migration := new(Migration)
	if err := db.Assign(Migration{}).FirstOrCreate(migration).Error; err != nil {
		return sqlError.Wrap(err)
	}

	schemaVersion := migration.Version

	log = log.With(telemetry.Schema, strconv.Itoa(schemaVersion))

	dbCodeVersion, err := getDBCodeVersion(*migration)
	if err != nil {
		log.Error("Error getting DB code version", "error", err.Error())
		return sqlError.New("error getting DB code version: %v", err)
	}

	log = log.With(telemetry.VersionInfo, dbCodeVersion.String())

	if schemaVersion == latestSchemaVersion {
		log.Debug("Code and DB schema versions are the same. No migration needed")

		// same DB schema; if current code version greater than stored, store newer code version
		if codeVersion.GT(dbCodeVersion) {
			newMigration := Migration{
				Version:     latestSchemaVersion,
				CodeVersion: codeVersion.String(),
			}

			if err := db.Model(&Migration{}).Updates(newMigration).Error; err != nil {
				return sqlError.Wrap(err)
			}
		}
		return nil
	}

	if disableMigration {
		if err = isDisabledMigrationAllowed(codeVersion, dbCodeVersion); err != nil {
			log.Error("Auto-migrate must be enabled", telemetry.Error, err)
			return sqlError.Wrap(err)
		}
		return nil
	}

	// The DB schema version can get ahead of us if the cluster is in the middle of
	// an upgrade. So long as the version is compatible, log a warning and continue.
	// Otherwise, we should bail out. Migration rollbacks are not supported.
	if schemaVersion > latestSchemaVersion {
		if !isCompatibleCodeVersion(codeVersion, dbCodeVersion) {
			log.Error("Incompatible DB schema is too new for code version, upgrade SPIRE Server")
			return sqlError.New("incompatible DB schema and code version")
		}
		log.Warn("DB schema is ahead of code version, upgrading SPIRE Server is recommended")
		return nil
	}

	// at this point:
	// - auto-migration is enabled
	// - schema version of DB is behind

	log.Info("Running migrations...")
	for schemaVersion < latestSchemaVersion {
		tx := db.Begin()
		if err := tx.Error; err != nil {
			return sqlError.Wrap(err)
		}
		schemaVersion, err = migrateVersion(tx, schemaVersion, log)
		if err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit().Error; err != nil {
			return sqlError.Wrap(err)
		}
	}

	log.Info("Done running migrations")
	return nil
}

func isDisabledMigrationAllowed(thisCodeVersion, dbCodeVersion semver.Version) error {
	// If auto-migrate is disabled and we are running a compatible version (+/- 1
	// minor from the stored code version) then we are done here
	if !isCompatibleCodeVersion(thisCodeVersion, dbCodeVersion) {
		return errors.New("auto-migration must be enabled for current DB")
	}
	return nil
}

func getDBCodeVersion(migration Migration) (dbCodeVersion semver.Version, err error) {
	// default to 0.0.0
	dbCodeVersion = semver.Version{}
	// we will have a blank code version from pre-0.9, and fresh, datastores
	if migration.CodeVersion != "" {
		dbCodeVersion, err = semver.Parse(migration.CodeVersion)
		if err != nil {
			return dbCodeVersion, fmt.Errorf("unable to parse code version from DB: %v", err)
		}
	}
	return dbCodeVersion, nil
}

func isCompatibleCodeVersion(thisCodeVersion, dbCodeVersion semver.Version) bool {
	// Apply a targeted exception in which 0.12.x is compatible with 1.0.x
	// as 0.12 is the last pre-1.0 release.
	//
	// TODO: Remove in 1.1.0
	if thisCodeVersion.Major == 0 && thisCodeVersion.Minor == 12 {
		if dbCodeVersion.Major == 1 && dbCodeVersion.Minor == 0 {
			return true
		}
	}
	if thisCodeVersion.Major == 1 && thisCodeVersion.Minor == 0 {
		if dbCodeVersion.Major == 0 && dbCodeVersion.Minor == 12 {
			return true
		}
	}

	// If major version is the same and minor version is +/- 1, versions are
	// compatible
	if dbCodeVersion.Major != thisCodeVersion.Major || (math.Abs(float64(int64(dbCodeVersion.Minor)-int64(thisCodeVersion.Minor))) > 1) {
		return false
	}
	return true
}

func initDB(db *gorm.DB, dbType string, log hclog.Logger) (err error) {
	log.Info("Initializing new database")
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

	if err := tx.Assign(Migration{
		Version:     latestSchemaVersion,
		CodeVersion: codeVersion.String(),
	}).FirstOrCreate(&Migration{}).Error; err != nil {
		tx.Rollback()
		return sqlError.Wrap(err)
	}

	if err := addFederatedRegistrationEntriesRegisteredEntryIDIndex(tx); err != nil {
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

func migrateVersion(tx *gorm.DB, currVersion int, log hclog.Logger) (versionOut int, err error) {
	log.Info("Migrating version", telemetry.VersionInfo, currVersion)

	// When a new version is added an entry must be included here that knows
	// how to bring the previous version up. The migrations are run
	// sequentially, each in its own transaction, to move from one version to
	// the next.
	migrations := []func(tx *gorm.DB) error{
		migrateToV1,
		migrateToV2,
		migrateToV3,
		migrateToV4,
		migrateToV5,
		migrateToV6,
		migrateToV7,
		migrateToV8,
		migrateToV9,
		migrateToV10,
		migrateToV11,
		migrateToV12,
		migrateToV13,
		migrateToV14,
		migrateToV15,
	}

	if currVersion >= len(migrations) {
		return currVersion, sqlError.New("no migration support for version %d", currVersion)
	}

	if err := migrations[currVersion](tx); err != nil {
		return currVersion, err
	}

	nextVersion := currVersion + 1
	if err := tx.Model(&Migration{}).Updates(Migration{
		Version:     nextVersion,
		CodeVersion: version.Version(),
	}).Error; err != nil {
		return currVersion, sqlError.Wrap(err)
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
		stmt := fmt.Sprintf("DELETE FROM %s WHERE deleted_at IS NOT NULL;", table) //nolint: gosec // table source is controlled
		if err := tx.Exec(stmt).Error; err != nil {
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

	var attestedNodes []*V3AttestedNode
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
	if err := tx.AutoMigrate(&V10RegisteredEntry{}).Error; err != nil {
		return sqlError.Wrap(err)
	}
	return nil
}

func migrateToV11(tx *gorm.DB) error {
	if err := addFederatedRegistrationEntriesRegisteredEntryIDIndex(tx); err != nil {
		return err
	}
	return nil
}

func migrateToV12(tx *gorm.DB) error {
	if err := tx.AutoMigrate(&Migration{}).Error; err != nil {
		return sqlError.Wrap(err)
	}
	return nil
}

func migrateToV13(tx *gorm.DB) error {
	if err := tx.AutoMigrate(&AttestedNode{}).Error; err != nil {
		return sqlError.Wrap(err)
	}
	return nil
}

func migrateToV14(tx *gorm.DB) error {
	if err := tx.AutoMigrate(&RegisteredEntry{}).Error; err != nil {
		return sqlError.Wrap(err)
	}
	return nil
}

func migrateToV15(tx *gorm.DB) error {
	return addAttestedNodeEntriesExpiresAtIndex(tx)
}

func addFederatedRegistrationEntriesRegisteredEntryIDIndex(tx *gorm.DB) error {
	// GORM creates the federated_registration_entries implicitly with a primary
	// key tuple (bundle_id, registered_entry_id). Unfortunately, MySQL5 does
	// not use the primary key index efficiently when joining by registered_entry_id
	// during registration entry list operations. We can't use gorm AutoMigrate
	// to introduce the index since there is no explicit struct to add tags to
	// so we have to manually create it.
	if err := tx.Table("federated_registration_entries").AddIndex("idx_federated_registration_entries_registered_entry_id", "registered_entry_id").Error; err != nil {
		return sqlError.Wrap(err)
	}
	return nil
}

func addAttestedNodeEntriesExpiresAtIndex(tx *gorm.DB) error {
	// GORM creates the federated_registration_entries implicitly with a primary
	// key tuple (bundle_id, registered_entry_id). Unfortunately, MySQL5 does
	// not use the primary key index efficiently when joining by registered_entry_id
	// during registration entry list operations. We can't use gorm AutoMigrate
	// to introduce the index since there is no explicit struct to add tags to
	// so we have to manually create it.
	if err := tx.Table("attested_node_entries").AddIndex("idx_attested_node_entries_expires_at", "expires_at").Error; err != nil {
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

// V10RegisteredEntry holds a registered entity entry
type V10RegisteredEntry struct {
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

// TableName gets table name for v10 registered entry
func (V10RegisteredEntry) TableName() string {
	return "registered_entries"
}

type V8Selector struct {
	Model

	RegisteredEntryID uint   `gorm:"unique_index:idx_selector_entry"`
	Type              string `gorm:"unique_index:idx_selector_entry"`
	Value             string `gorm:"unique_index:idx_selector_entry"`
}

type V11Migration struct {
	Model

	// Database version
	Version int
}

// TableName gets table name for v11 migrations table
func (V11Migration) TableName() string {
	return "migrations"
}
