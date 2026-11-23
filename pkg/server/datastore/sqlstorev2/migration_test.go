package sqlstorev2

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/blang/semver/v4"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestMigrateDBFreshDatabase(t *testing.T) {
	log, _ := test.NewNullLogger()
	db := openGormV2(t)

	require.NoError(t, migrateDB(db, "sqlite3", false, log))

	// Migration row exists at the latest version.
	var m Migration
	require.NoError(t, db.First(&m).Error)
	require.Equal(t, latestSchemaVersion, m.Version)
	require.Equal(t, codeVersion.String(), m.CodeVersion)

	// The join-table index declared on FederatedRegistrationEntry exists.
	require.True(t, db.Migrator().HasIndex("federated_registration_entries", "idx_federated_registration_entries_registered_entry_id"))

	// Second call is a no-op (already at latest).
	require.NoError(t, migrateDB(db, "sqlite3", false, log))
}

func TestMigrateDBStampsNewerCodeVersion(t *testing.T) {
	log, _ := test.NewNullLogger()
	db := openGormV2(t)

	// Establish the full current schema at the latest version.
	require.NoError(t, migrateDB(db, "sqlite3", false, log))

	// Leave the schema version at latest but roll the stored code version back
	// to an older release, so codeVersion.GT(dbCodeVersion) is true.
	var seeded Migration
	require.NoError(t, db.First(&seeded).Error)
	require.NoError(t, db.Model(&Migration{}).Where("id = ?", seeded.ID).Updates(map[string]any{
		"code_version": "1.8.0",
	}).Error)

	require.NoError(t, migrateDB(db, "sqlite3", false, log))

	var m Migration
	require.NoError(t, db.First(&m).Error)
	require.Equal(t, latestSchemaVersion, m.Version)
	require.Equal(t, codeVersion.String(), m.CodeVersion)
}

func TestMigrateDBBranches(t *testing.T) {
	sameMinor := codeVersion.String()
	nextMinor := fmt.Sprintf("%d.%d.0", codeVersion.Major, codeVersion.Minor+1)
	farMinor := fmt.Sprintf("%d.%d.0", codeVersion.Major, codeVersion.Minor+2)

	for _, tt := range []struct {
		name             string
		version          int
		codeVersion      string
		setupSQL         string
		disableMigration bool
		expectErr        string
		expectVersion    int
	}{
		{
			name:             "disabled migration with compatible code version leaves schema behind",
			version:          latestSchemaVersion - 1,
			codeVersion:      sameMinor,
			disableMigration: true,
			expectVersion:    latestSchemaVersion - 1,
		},
		{
			name:             "disabled migration with incompatible code version",
			version:          latestSchemaVersion - 1,
			codeVersion:      farMinor,
			disableMigration: true,
			expectErr:        "datastore-sql: auto-migration must be enabled for current DB",
		},
		{
			name:          "schema newer than code with compatible code version",
			version:       latestSchemaVersion + 1,
			codeVersion:   nextMinor,
			expectVersion: latestSchemaVersion + 1,
		},
		{
			name:        "schema newer than code with incompatible code version",
			version:     latestSchemaVersion + 1,
			codeVersion: farMinor,
			expectErr:   "datastore-sql: incompatible DB schema and code version",
		},
		{
			name:        "schema older than the last minor release",
			version:     lastMinorReleaseSchemaVersion - 1,
			codeVersion: sameMinor,
			expectErr:   fmt.Sprintf("datastore-sql: migrating from schema version %d requires a previous SPIRE release; please follow the upgrade strategy at doc/upgrading.md", lastMinorReleaseSchemaVersion-1),
		},
		{
			name:        "unparseable code version",
			version:     latestSchemaVersion - 1,
			codeVersion: "not-a-version",
			expectErr:   "datastore-sql: error getting DB code version: unable to parse code version from DB: No Major.Minor.Patch elements found",
		},
		{
			name:      "empty migrations table",
			setupSQL:  "DELETE FROM migrations",
			expectErr: "datastore-sql: migrations table has no row",
		},
		{
			name:          "duplicate migrations rows upgrade the lowest id",
			setupSQL:      "INSERT INTO migrations (version, code_version) SELECT version, code_version FROM migrations; UPDATE migrations SET version = 26 WHERE id = (SELECT MIN(id) FROM migrations)",
			expectVersion: latestSchemaVersion,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			log, _ := test.NewNullLogger()
			db := openGormV2(t)
			require.NoError(t, migrateDB(db, "sqlite3", false, log))

			if tt.setupSQL != "" {
				require.NoError(t, db.Exec(tt.setupSQL).Error)
			} else {
				require.NoError(t, db.Exec("UPDATE migrations SET version = ?, code_version = ?", tt.version, tt.codeVersion).Error)
			}

			err := migrateDB(db, "sqlite3", tt.disableMigration, log)
			if tt.expectErr != "" {
				require.EqualError(t, err, tt.expectErr)
				return
			}
			require.NoError(t, err)

			var m Migration
			require.NoError(t, db.First(&m).Error)
			require.Equal(t, tt.expectVersion, m.Version)
		})
	}
}

func TestMigrateDBRerunsAppliedSteps(t *testing.T) {
	log, _ := test.NewNullLogger()
	db := openGormV2(t)
	require.NoError(t, migrateDB(db, "sqlite3", false, log))
	require.NoError(t, db.Exec("UPDATE migrations SET version = ?", lastMinorReleaseSchemaVersion).Error)

	require.NoError(t, migrateDB(db, "sqlite3", false, log))

	var m Migration
	require.NoError(t, db.First(&m).Error)
	require.Equal(t, latestSchemaVersion, m.Version)
}

func openGormV2(t *testing.T) *gorm.DB {
	dbPath := filepath.ToSlash(filepath.Join(t.TempDir(), "m.sqlite3"))
	db, err := gorm.Open(sqlite.Open(dbPath), gormConfig())
	require.NoError(t, err)
	raw, err := db.DB()
	require.NoError(t, err)
	// Registered after t.TempDir, so it runs first: Windows cannot remove a
	// file that is still open.
	t.Cleanup(func() { require.NoError(t, raw.Close()) })
	require.NoError(t, setupJoinTables(db))
	return db
}

func TestInitDBKeepsExistingMigrationRow(t *testing.T) {
	log, _ := test.NewNullLogger()
	db := openGormV2(t)
	require.NoError(t, migrateDB(db, "sqlite3", false, log))
	require.NoError(t, db.Exec("UPDATE migrations SET version = ?", lastMinorReleaseSchemaVersion).Error)

	require.NoError(t, initDB(db, "sqlite3", log))

	var migrations []Migration
	require.NoError(t, db.Find(&migrations).Error)
	require.Len(t, migrations, 1)
	require.Equal(t, lastMinorReleaseSchemaVersion, migrations[0].Version)
}

func TestGetDBCodeVersion(t *testing.T) {
	tests := []struct {
		desc            string
		storedMigration Migration
		expectVersion   semver.Version
		expectErr       string
	}{
		{
			desc:            "no code version",
			storedMigration: Migration{},
			expectVersion:   semver.Version{},
		},
		{
			desc:            "code version, valid",
			storedMigration: Migration{CodeVersion: "1.2.3"},
			expectVersion:   semver.Version{Major: 1, Minor: 2, Patch: 3, Pre: nil, Build: nil},
		},
		{
			desc:            "code version, invalid",
			storedMigration: Migration{CodeVersion: "a.2*.3"},
			expectErr:       "unable to parse code version from DB: Invalid character(s) found in major number \"a\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			retVersion, err := getDBCodeVersion(tt.storedMigration)

			if tt.expectErr != "" {
				assert.Equal(t, semver.Version{}, retVersion)
				assert.Equal(t, tt.expectErr, err.Error())
				return
			}

			assert.Equal(t, tt.expectVersion, retVersion)
			assert.NoError(t, err)
		})
	}
}

func TestIsCompatibleCodeVersion(t *testing.T) {
	tests := []struct {
		desc             string
		thisCodeVersion  semver.Version
		dbCodeVersion    semver.Version
		expectCompatible bool
	}{
		{
			desc:             "backwards compatible 1 minor version",
			thisCodeVersion:  codeVersion,
			dbCodeVersion:    semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor - 1)},
			expectCompatible: true,
		},
		{
			desc:             "forwards compatible 1 minor version",
			thisCodeVersion:  codeVersion,
			dbCodeVersion:    semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor + 1)},
			expectCompatible: true,
		},
		{
			desc:             "compatible with self",
			thisCodeVersion:  codeVersion,
			dbCodeVersion:    codeVersion,
			expectCompatible: true,
		},
		{
			desc:             "not backwards compatible 2 minor versions",
			thisCodeVersion:  codeVersion,
			dbCodeVersion:    semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor - 2)},
			expectCompatible: false,
		},
		{
			desc:             "not forwards compatible 2 minor versions",
			thisCodeVersion:  codeVersion,
			dbCodeVersion:    semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor + 2)},
			expectCompatible: false,
		},
		{
			desc:             "not compatible with different major version but same minor",
			thisCodeVersion:  codeVersion,
			dbCodeVersion:    semver.Version{Major: (codeVersion.Major + 1), Minor: codeVersion.Minor},
			expectCompatible: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			compatible := isCompatibleCodeVersion(tt.thisCodeVersion, tt.dbCodeVersion)

			assert.Equal(t, tt.expectCompatible, compatible)
		})
	}
}

func TestIsDisabledMigrationAllowed(t *testing.T) {
	tests := []struct {
		desc          string
		dbCodeVersion semver.Version
		expectErr     string
	}{
		{
			desc:          "allowed",
			dbCodeVersion: semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor + 1)},
		},
		{
			desc:          "not allowed, versioning",
			dbCodeVersion: semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor + 2)},
			expectErr:     "auto-migration must be enabled for current DB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			err := isDisabledMigrationAllowed(codeVersion, tt.dbCodeVersion)

			if tt.expectErr != "" {
				require.Error(t, err)
				assert.Equal(t, tt.expectErr, err.Error())
				return
			}

			assert.NoError(t, err)
		})
	}
}
