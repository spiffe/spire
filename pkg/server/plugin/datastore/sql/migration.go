package sql

import (
	"fmt"

	"github.com/jinzhu/gorm"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/idutil"
)

const (
	// version of the database in the code
	codeVersion = 3
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

	if err := tx.AutoMigrate(&Bundle{}, &CACert{}, &AttestedNode{},
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

	var bundles []*Bundle
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

	var registeredEntries []*RegisteredEntry
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
