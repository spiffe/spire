package sqlstorev2

import (
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/blang/semver/v4"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/version"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"gorm.io/gorm"
)

// Each time the database requires a migration, the "schema" version is
// increased and the migration code is added to this file. The migration code
// can be opportunistically removed after the following minor version has been
// released, since the supported upgrade path happens on minor version
// boundaries. For example, when 1.2 is released, the migrations that were
// handled by 1.1.x can be removed, since anyone upgrading from 1.0.X to 1.2.X
// will have to upgrade through 1.1.X first, which will apply the proper
// migrations before those done by 1.2.
//
// For convenience, the following table lists the schema versions for each
// SPIRE release, along with what was added in each schema change. SPIRE v0.6.2
// was the first version to introduce migrations.
//
// ================================================================================================
// | SPIRE   | Schema | What changed                                                              |
// ================================================================================================
// | v0.6.2  | 1      | Soft delete support was removed                                           |
// |*********|********|***************************************************************************|
// | v0.7.0  | 2      | Created join table between bundles and entries                            |
// |         |--------|---------------------------------------------------------------------------|
// |         | 3      | Normalized trust domain IDs across all tables                             |
// |         |--------|---------------------------------------------------------------------------|
// |         | 4      | Converted bundle data from DER to protobuf                                |
// |---------|        |                                                                           |
// | v0.7.1  |        |                                                                           |
// |---------|--------|---------------------------------------------------------------------------|
// | v0.7.2  | 5      | Added admin column to Entries                                             |
// |---------|        |                                                                           |
// | v0.7.3  |        |                                                                           |
// |*********|********|***************************************************************************|
// | v0.8.0  | 6      | Added downstream column to entries                                        |
// |         |--------|---------------------------------------------------------------------------|
// |         | 7      | Added expiry column to entries                                            |
// |         |--------|---------------------------------------------------------------------------|
// |         | 8      | Added dns name support for entries                                        |
// |---------|--------|---------------------------------------------------------------------------|
// | v0.8.1  | 9      | Added parent ID, SPIFFE ID and selector indices for entries               |
// |---------|--------|---------------------------------------------------------------------------|
// | v0.8.2  | 10     | Added expiry index for entries                                            |
// |         |--------|---------------------------------------------------------------------------|
// |         | 11     | Added federates with index for entries                                    |
// |---------|        |                                                                           |
// | v0.8.3  |        |                                                                           |
// |---------|        |                                                                           |
// | v0.8.4  |        |                                                                           |
// |---------|        |                                                                           |
// | v0.8.5  |        |                                                                           |
// |*********|********|***************************************************************************|
// | v0.9.0  | 12     | Added support for tracking the code version in the migration table        |
// |         |--------|---------------------------------------------------------------------------|
// |         | 13     | Added "prepared" cert columns to the attested nodes                       |
// |---------|        |                                                                           |
// | v0.9.1  |        |                                                                           |
// |---------|        |                                                                           |
// | v0.9.2  |        |                                                                           |
// |---------|        |                                                                           |
// | v0.9.3  |        |                                                                           |
// |---------|        |                                                                           |
// | v0.9.4  |        |                                                                           |
// |*********|********|***************************************************************************|
// | v0.10.0 | 14     | Added revision number column to entries                                   |
// |---------|        |                                                                           |
// | v0.10.1 |        |                                                                           |
// |---------|        |                                                                           |
// | v0.10.2 |        |                                                                           |
// |*********|        |                                                                           |
// | v0.11.0 |        |                                                                           |
// |---------|        |                                                                           |
// | v0.11.1 |        |                                                                           |
// |---------|        |                                                                           |
// | v0.11.2 |        |                                                                           |
// |---------|        |                                                                           |
// | v0.11.2 |        |                                                                           |
// |*********|********|***************************************************************************|
// | v0.12.0 | 15     | Added expiry index to attested nodes                                      |
// |---------|        |                                                                           |
// | v0.12.1 |        |                                                                           |
// |---------|        |                                                                           |
// | v0.12.2 |        |                                                                           |
// |---------|        |                                                                           |
// | v0.12.3 |        |                                                                           |
// |*********|********|***************************************************************************|
// | v1.0.0  | 16     | Added exportable identity column to entries                               |
// |         |--------|---------------------------------------------------------------------------|
// |         | 17     | Added support for Federated Trust Domains relationships                   |
// |---------|        |---------------------------------------------------------------------------|
// | v1.0.1  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.0.2  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.0.3  |        |                                                                           |
// |*********|        |                                                                           |
// | v1.1.0  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.1.1  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.1.2  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.1.3  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.1.4  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.1.5  |        |                                                                           |
// |*********|********|***************************************************************************|
// | v1.2.0  | 18     | Added hint column to entries and can_reattest column to attested nodes    |
// |---------|        |                                                                           |
// | v1.2.1  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.2.2  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.2.3  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.2.4  |        |                                                                           |
// |*********|        |                                                                           |
// | v1.3.0  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.3.1  |        |                                                                           |
// |---------|--------|---------------------------------------------------------------------------|
// | v1.3.2  | 19     | Added x509_svid_ttl and jwt_svid_ttl columns to entries                   |
// |---------|        |                                                                           |
// | v1.3.3  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.3.4  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.3.5  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.3.6  |        |                                                                           |
// |*********|********|***************************************************************************|
// | v1.4.0  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.4.1  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.4.2  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.4.3  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.4.4  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.4.5  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.4.6  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.4.7  |        |                                                                           |
// |*********|********|***************************************************************************|
// | v1.5.0  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.5.1  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.5.2  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.5.3  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.5.4  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.5.5  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.5.6  |        |                                                                           |
// |*********|********|***************************************************************************|
// | v1.6.0  | 20     | Removed x509_svid_ttl column from registered_entries                      |
// |         |--------|---------------------------------------------------------------------------|
// |         | 21     | Added index in hint column from registered_entries                        |
// |---------|        |                                                                           |
// | v1.6.1  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.6.2  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.6.3  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.6.4  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.6.5  |        |                                                                           |
// |*********|********|***************************************************************************|
// | v1.7.0  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.7.1  |        |                                                                           |
// |---------|--------|---------------------------------------------------------------------------|
// | v1.7.2  | 22     | Added registered_entries_events and attested_node_entries_events tables   |
// |---------|        |                                                                           |
// | v1.7.3  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.7.4  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.7.5  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.7.6  |        |                                                                           |
// |*********|********|***************************************************************************|
// | v1.8.0  | 23     | Added ca_journals table                                                   |
// |---------|        |                                                                           |
// | v1.8.1  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.8.2  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.8.3  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.8.4  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.8.5  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.8.6  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.8.7  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.8.8  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.8.9  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.8.10 |        |                                                                           |
// |---------|        |                                                                           |
// | v1.8.11 |        |                                                                           |
// |*********|********|***************************************************************************|
// | v1.9.0  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.9.1  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.9.2  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.9.3  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.9.4  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.9.5  |        |                                                                           |
// |---------|        |                                                                           |
// | v1.9.6  |        |                                                                           |
// |*********|********|***************************************************************************|
// | v1.10.0 |        |                                                                           |
// |---------|        |                                                                           |
// | v1.10.1 |        |                                                                           |
// |---------|        |                                                                           |
// | v1.10.2 |        |                                                                           |
// |---------|        |                                                                           |
// | v1.10.3 |        |                                                                           |
// |---------|        |                                                                           |
// | v1.10.4 |        |                                                                           |
// |*********|********|***************************************************************************|
// | v1.11.0 |        |                                                                           |
// |---------|        |                                                                           |
// | v1.11.1 |        |                                                                           |
// |---------|        |                                                                           |
// | v1.11.2 |        |                                                                           |
// |---------|        |                                                                           |
// | v1.11.3 |        |                                                                           |
// |*********|********|***************************************************************************|
// | v1.12.0 |        |                                                                           |
// | v1.12.1 |        |                                                                           |
// | v1.12.2 |        |                                                                           |
// | v1.12.3 |        |                                                                           |
// | v1.12.4 |        |                                                                           |
// | v1.12.5 |        |                                                                           |
// | v1.12.6 |        |                                                                           |
// |*********|********|***************************************************************************|
// | v1.13.0 |        |                                                                           |
// | v1.13.1 |        |                                                                           |
// | v1.13.2 |        |                                                                           |
// | v1.13.3 |        |                                                                           |
// | v1.13.4 |        |                                                                           |
// | v1.13.5 |        |                                                                           |
// |*********|********|***************************************************************************|
// | v1.14.0 |        |                                                                           |
// | v1.14.1 |        |                                                                           |
// | v1.14.2 |        |                                                                           |
// | v1.14.3 | 24     | Added agent_version column to attested_node_entries                       |
// | v1.14.4 |        |                                                                           |
// | v1.14.5 |        |                                                                           |
// | v1.14.6 |        |                                                                           |
// | v1.14.7 |        |                                                                           |
// |*********|********|***************************************************************************|
// | v1.15.0 | 25     | Added additional_attributes column to registered_entries                  |
// | v1.15.1 |        |                                                                           |
// | v1.15.2 |        |                                                                           |
// | v1.15.3 |        |                                                                           |
// |*********|********|***************************************************************************|
// | v1.16.0 | 26     | Added journal_id column to ca_journals                                    |
// |         |--------|---------------------------------------------------------------------------|
// |         | 27     | Added wit_svid_ttl column to registered_entries                           |
// ================================================================================================

const (
	// latestSchemaVersion is the latest database schema version in the code.
	latestSchemaVersion = 27

	// lastMinorReleaseSchemaVersion is the schema version supported by the last
	// minor release. Update when migrations are pruned after a minor release.
	lastMinorReleaseSchemaVersion = 23
)

// codeVersion is the current SPIRE code version.
var codeVersion = semver.MustParse(version.Version())

func migrateDB(db *gorm.DB, dbType string, disableMigration bool, log logrus.FieldLogger) (err error) {
	// The version comparison logic supports only 0.x and 1.x. Fail if we're
	// building a 2.x, so the logic gets revisited before release.
	if codeVersion.Major > 1 {
		log.Error("Migration code needs updating for current release version")
		return sqlcommon.NewSQLError("current migration code not compatible with current release version")
	}

	isNew, err := isNewDB(db, dbType)
	if err != nil {
		return err
	}
	if isNew {
		return initDB(db, dbType, log)
	}

	var migrations []Migration
	if err := db.Order("id").Limit(2).Find(&migrations).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}
	switch {
	case len(migrations) > 1:
		// Concurrent initializations on MySQL can each record a row. The row
		// with the lowest id is always the one read and updated, so the others
		// are ignored.
		log.Warn("Migrations table has more than one row, using the one with the lowest id; the other rows are unused and can be deleted")
	case len(migrations) == 0 && sqlcommon.IsMySQLDbType(dbType):
		// initDB records the migration row last, so a migrations table without
		// one was left by an initialization that failed partway through on
		// MySQL, where each DDL statement commits implicitly, or is still
		// running on another server. initDB only creates what is missing, so
		// it is run again to finish the job.
		if disableMigration {
			return sqlcommon.NewSQLError("database initialization did not complete; another server may still be initializing it, otherwise auto-migration must be enabled to finish it")
		}
		log.Warn("Database initialization did not complete, resuming it; another server may still be initializing it")
		return initDB(db, dbType, log)
	case len(migrations) == 0:
		// initDB is transactional on other databases, so a missing row was
		// not left by a failed initialization and the schema version is
		// unknown.
		return sqlcommon.NewSQLError("migrations table has no row")
	}
	migration := migrations[0]

	schemaVersion := migration.Version

	log = log.WithField(telemetry.Schema, strconv.Itoa(schemaVersion))

	dbCodeVersion, err := getDBCodeVersion(migration)
	if err != nil {
		log.WithError(err).Error("Error getting DB code version")
		return sqlcommon.NewWrappedSQLError(fmt.Errorf("error getting DB code version: %w", err))
	}

	log = log.WithField(telemetry.VersionInfo, dbCodeVersion.String())

	if schemaVersion == latestSchemaVersion {
		log.Debug("Code and DB schema versions are the same. No migration needed")
		if codeVersion.GT(dbCodeVersion) {
			newMigration := Migration{
				Version:     latestSchemaVersion,
				CodeVersion: codeVersion.String(),
			}
			if err := updateMigration(db, migration.ID, newMigration); err != nil {
				return err
			}
		}
		return nil
	}

	if disableMigration {
		if err = isDisabledMigrationAllowed(codeVersion, dbCodeVersion); err != nil {
			log.WithError(err).Error("Auto-migrate must be enabled")
			return sqlcommon.NewWrappedSQLError(err)
		}
		if schemaVersion < latestSchemaVersion {
			log.Warn("Auto-migration is disabled and the DB schema is behind the code version")
		}
		return nil
	}

	// The DB schema version can get ahead during a cluster upgrade. If
	// compatible, warn and continue; otherwise bail (no rollbacks).
	if schemaVersion > latestSchemaVersion {
		if !isCompatibleCodeVersion(codeVersion, dbCodeVersion) {
			log.Error("Incompatible DB schema is too new for code version, upgrade SPIRE Server")
			return sqlcommon.NewSQLError("incompatible DB schema and code version")
		}
		log.Warn("DB schema is ahead of code version, upgrading SPIRE Server is recommended")
		return nil
	}

	// auto-migration enabled and schema behind: migrate forward.
	log.Info("Running migrations...")
	for schemaVersion < latestSchemaVersion {
		tx := db.Begin()
		if err := tx.Error; err != nil {
			return sqlcommon.NewWrappedSQLError(err)
		}
		schemaVersion, err = migrateVersion(tx, migration.ID, schemaVersion, log)
		if err != nil {
			return errors.Join(err, tx.Rollback().Error)
		}
		if err := tx.Commit().Error; err != nil {
			return sqlcommon.NewWrappedSQLError(err)
		}
	}

	log.Info("Done running migrations")
	return nil
}

// isNewDB reports whether the database has no migrations table. It queries
// the catalog itself because gorm's table lookups discard errors (on MySQL,
// failing to resolve the current database makes them search another schema),
// and treating an existing database as new would run initDB against it.
func isNewDB(db *gorm.DB, dbType string) (bool, error) {
	var query string
	switch {
	case sqlcommon.IsMySQLDbType(dbType):
		query = "SELECT DATABASE(), (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'migrations')"
	case sqlcommon.IsPostgresDbType(dbType):
		query = "SELECT current_schema(), (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'migrations')"
	default:
		query = "SELECT 'main', (SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'migrations')"
	}
	var schema sql.NullString
	var count int
	if err := db.Raw(query).Row().Scan(&schema, &count); err != nil {
		return false, sqlcommon.NewWrappedSQLError(err)
	}
	if !schema.Valid {
		return false, sqlcommon.NewSQLError("no current database or schema is selected")
	}
	return count == 0, nil
}

func isDisabledMigrationAllowed(thisCodeVersion, dbCodeVersion semver.Version) error {
	// If auto-migrate is disabled and we're within +/- 1 minor of the stored
	// version, we're done.
	if !isCompatibleCodeVersion(thisCodeVersion, dbCodeVersion) {
		return errors.New("auto-migration must be enabled for current DB")
	}
	return nil
}

func getDBCodeVersion(migration Migration) (dbCodeVersion semver.Version, err error) {
	// default to 0.0.0; blank code version comes from pre-0.9 DBs.
	dbCodeVersion = semver.Version{}
	if migration.CodeVersion != "" {
		dbCodeVersion, err = semver.Parse(migration.CodeVersion)
		if err != nil {
			return dbCodeVersion, fmt.Errorf("unable to parse code version from DB: %w", err)
		}
	}
	return dbCodeVersion, nil
}

func isCompatibleCodeVersion(thisCodeVersion, dbCodeVersion semver.Version) bool {
	// Same major and minor +/- 1 => compatible.
	minMinor, maxMinor := min(dbCodeVersion.Minor, thisCodeVersion.Minor), max(dbCodeVersion.Minor, thisCodeVersion.Minor)
	return dbCodeVersion.Major == thisCodeVersion.Major && (minMinor == maxMinor || minMinor+1 == maxMinor)
}

func initDB(db *gorm.DB, dbType string, log logrus.FieldLogger) (err error) {
	log.Info("Initializing new database")
	tx := db.Begin()
	if err := tx.Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}

	tables := []any{
		&Bundle{},
		&AttestedNode{},
		&AttestedNodeEvent{},
		&NodeSelector{},
		&RegisteredEntry{},
		&RegisteredEntryEvent{},
		&JoinToken{},
		&Selector{},
		&Migration{},
		&DNSName{},
		&FederatedTrustDomain{},
		&CAJournal{},
	}

	if err := tableOptionsForDialect(tx, dbType).AutoMigrate(tables...); err != nil {
		return errors.Join(sqlcommon.NewWrappedSQLError(err), tx.Rollback().Error)
	}

	// Recorded last so that, on MySQL where each DDL statement commits
	// implicitly, a failed initialization leaves no migration row and is
	// resumed by the next migrateDB call. Attrs leaves a row that already
	// exists untouched, so its version is never overwritten.
	if err := tx.Attrs(Migration{
		Version:     latestSchemaVersion,
		CodeVersion: codeVersion.String(),
	}).FirstOrCreate(&Migration{}).Error; err != nil {
		return errors.Join(sqlcommon.NewWrappedSQLError(err), tx.Rollback().Error)
	}

	if err := tx.Commit().Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}

	return nil
}

func tableOptionsForDialect(tx *gorm.DB, dbType string) *gorm.DB {
	// For MySQL, ensure indexes on varchar(255) strings work by setting the
	// engine/charset table options (compatibility with v1 schema).
	if sqlcommon.IsMySQLDbType(dbType) {
		return tx.Set("gorm:table_options", "ENGINE=InnoDB  ROW_FORMAT=DYNAMIC DEFAULT CHARSET=utf8")
	}
	return tx
}

func migrateVersion(
	tx *gorm.DB, migrationID uint, currVersion int, log logrus.FieldLogger,
) (versionOut int, err error) {
	log.WithField(telemetry.VersionInfo, currVersion).Info("Migrating version")

	nextVersion := currVersion + 1

	if currVersion < lastMinorReleaseSchemaVersion {
		return 0, sqlcommon.NewSQLError("migrating from schema version %d requires a previous SPIRE release; please follow the upgrade strategy at doc/upgrading.md", currVersion)
	}

	switch currVersion {
	case 23:
		err = migrateToV24(tx)
	case 24:
		err = migrateToV25(tx)
	case 25:
		err = migrateToV26(tx)
	case 26:
		err = migrateToV27(tx)
	default:
		return 0, sqlcommon.NewSQLError("no migration support for unknown schema version %d", currVersion)
	}
	if err != nil {
		return 0, sqlcommon.NewWrappedSQLError(fmt.Errorf("migrating schema version %d to %d: %w", currVersion, nextVersion, err))
	}

	// The version is recorded after the step's DDL because MySQL commits
	// implicitly before each DDL statement. Recording it first could mark a
	// step that failed partway through as done, so it would never be retried.
	if err := updateMigration(tx, migrationID, Migration{
		Version:     nextVersion,
		CodeVersion: version.Version(),
	}); err != nil {
		return 0, err
	}

	return nextVersion, nil
}

func migrateToV24(tx *gorm.DB) error {
	return addColumnIfMissing(tx, &AttestedNode{}, "agent_version")
}

func migrateToV25(tx *gorm.DB) error {
	return addColumnIfMissing(tx, &RegisteredEntry{}, "additional_attributes")
}

func migrateToV26(tx *gorm.DB) error {
	if err := addColumnIfMissing(tx, &CAJournal{}, "journal_id"); err != nil {
		return err
	}
	return createIndexIfMissing(tx, &CAJournal{}, "uix_ca_journals_journal_id")
}

func migrateToV27(tx *gorm.DB) error {
	return addColumnIfMissing(tx, &RegisteredEntry{}, "wit_svid_ttl")
}

// updateMigration updates the migration row with the given id. The number of
// rows affected is not checked: MySQL counts only rows whose values changed,
// so a server repeating an identical update within the same second would see
// zero.
func updateMigration(db *gorm.DB, id uint, migration Migration) error {
	// gorm refuses an Updates() call without a WHERE clause.
	if err := db.Model(&Migration{}).Where("id = ?", id).Updates(migration).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}
	return nil
}

// addColumnIfMissing adds column to model's table unless it already exists,
// so a step that failed partway through can be run again. Upgrade steps use
// it instead of AutoMigrate, which also alters existing columns whose type
// differs from the model (e.g. varchar(255) versus text) and on SQLite does so
// by rebuilding the whole table. It lists the columns rather than using
// Migrator().HasColumn, which discards lookup errors.
func addColumnIfMissing(tx *gorm.DB, model any, column string) error {
	columns, err := tx.Migrator().ColumnTypes(model)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(columns, func(c gorm.ColumnType) bool { return c.Name() == column }) {
		return nil
	}
	return tx.Migrator().AddColumn(model, column)
}

// createIndexIfMissing creates the named index declared on model unless it
// already exists. It lists the indexes rather than using Migrator().HasIndex,
// which discards lookup errors.
func createIndexIfMissing(tx *gorm.DB, model any, name string) error {
	indexes, err := tx.Migrator().GetIndexes(model)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(indexes, func(i gorm.Index) bool { return i.Name() == name }) {
		return nil
	}
	return tx.Migrator().CreateIndex(model, name)
}

// setupJoinTables makes gorm use FederatedRegistrationEntry for
// federated_registration_entries, both to create the table and to query it,
// instead of deriving a join model from the many2many relationships. It must
// run on every new connection before the models are used.
func setupJoinTables(db *gorm.DB) error {
	if err := db.SetupJoinTable(&RegisteredEntry{}, "FederatesWith", &FederatedRegistrationEntry{}); err != nil {
		return err
	}
	return db.SetupJoinTable(&Bundle{}, "FederatedEntries", &FederatedRegistrationEntry{})
}
