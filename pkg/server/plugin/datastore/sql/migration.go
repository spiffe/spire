package sql

import (
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jinzhu/gorm"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
)

const (
	// version of the database in the code
	codeVersion = 7
)

func migrateDB(db *gorm.DB) (err error) {
	isNew := !db.HasTable(&Bundle{})
	if err := db.Error; err != nil {
		return sqlError.Wrap(err)
	}

	if isNew {
		return initDB(db)
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
		logrus.Error(err)
		return err
	}

	if version == codeVersion {
		return nil
	}

	logrus.Infof("running migrations...")
	for version < codeVersion {
		tx := db.Begin()
		if err := tx.Error; err != nil {
			return sqlError.Wrap(err)
		}
		version, err = migrateVersion(tx, version)
		if err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit().Error; err != nil {
			return sqlError.Wrap(err)
		}
	}

	logrus.Infof("done running migrations.")
	return nil
}

func initDB(db *gorm.DB) (err error) {
	logrus.Infof("initializing database.")
	tx := db.Begin()
	if err := tx.Error; err != nil {
		return sqlError.Wrap(err)
	}

	if err := tx.AutoMigrate(&Bundle{}, &AttestedNode{},
		&NodeSelector{}, &RegisteredEntry{}, &JoinToken{},
		&Selector{}, &Migration{}).Error; err != nil {
		tx.Rollback()
		return sqlError.Wrap(err)
	}

	if err := tx.Assign(Migration{Version: codeVersion}).FirstOrCreate(&Migration{}).Error; err != nil {
		tx.Rollback()
		return sqlError.Wrap(err)
	}

	if err := tx.Commit().Error; err != nil {
		return sqlError.Wrap(err)
	}

	return nil
}

func migrateVersion(tx *gorm.DB, version int) (versionOut int, err error) {
	logrus.Infof("migrating from version %d", version)

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
	if err := tx.AutoMigrate(&RegisteredEntry{}).Error; err != nil {
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
	Selectors     []Selector
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
	Selectors     []Selector
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
	Selectors     []Selector
	FederatesWith []Bundle `gorm:"many2many:federated_registration_entries;"`
	Admin         bool
	Downstream    bool
}

// TableName gets table name for v6 registered entry
func (V6RegisteredEntry) TableName() string {
	return "registered_entries"
}
