package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/datastore/sqltest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	ctx = context.Background()

	// The following are set by the linker during integration tests to
	// run these unit tests against various SQL backends.
	TestDialect      string
	TestConnString   string
	TestROConnString string
)

// TestPlugin runs the shared datastore conformance suite against the
// sqlstore v1 plugin.
func TestPlugin(t *testing.T) {
	sqltest.Run(t, sqltest.Config{
		NewDataStore: func(log logrus.FieldLogger) sqltest.DataStoreUnderTest {
			return New(log)
		},
		Dialect:               TestDialect,
		ConnString:            TestConnString,
		ROConnString:          TestROConnString,
		ExpectedSchemaVersion: latestSchemaVersion,
		ExpectedCodeVersion:   codeVersion.String(),
	})
}

// newTestPlugin builds a fresh sqlite3-backed *Plugin for whitebox tests
// that need direct access to unexported sqlstore internals (gorm models,
// migration state, raw query builders) and therefore cannot run through the
// sqltest.DataStoreUnderTest interface.
func newTestPlugin(t *testing.T) *Plugin {
	log, _ := test.NewNullLogger()
	ds := New(log)
	t.Cleanup(func() {
		ds.Close()
	})

	dbPath := filepath.ToSlash(filepath.Join(t.TempDir(), "db.sqlite3"))
	err := ds.Configure(ctx, fmt.Sprintf(`
		database_type = "sqlite3"
		log_sql = true
		connection_string = "%s"
	`, dbPath))
	require.NoError(t, err)

	return ds
}

func TestBindVar(t *testing.T) {
	fn := func(n int) string {
		return fmt.Sprintf("$%d", n)
	}
	bound := bindVarsFn(fn, "SELECT whatever FROM foo WHERE x = ? AND y = ?")
	require.Equal(t, "SELECT whatever FROM foo WHERE x = $1 AND y = $2", bound)
}

func TestBuildQuestionsAndPlaceholders(t *testing.T) {
	for _, tt := range []struct {
		name                 string
		entries              []string
		expectedQuestions    string
		expectedPlaceholders string
	}{
		{
			name:                 "No args",
			expectedQuestions:    "",
			expectedPlaceholders: "",
		},
		{
			name:                 "One arg",
			entries:              []string{"a"},
			expectedQuestions:    "?",
			expectedPlaceholders: "$1",
		},
		{
			name:                 "Five args",
			entries:              []string{"a", "b", "c", "e", "f"},
			expectedQuestions:    "?,?,?,?,?",
			expectedPlaceholders: "$1,$2,$3,$4,$5",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			questions := buildQuestions(tt.entries)
			require.Equal(t, tt.expectedQuestions, questions)
			placeholders := buildPlaceholders(tt.entries)
			require.Equal(t, tt.expectedPlaceholders, placeholders)
		})
	}
}

func TestConfigure(t *testing.T) {
	tests := []struct {
		desc               string
		giveDBConfig       string
		expectMaxOpenConns int
		expectIdle         int
	}{
		{
			desc:               "defaults",
			expectMaxOpenConns: 100,
			// defined in database/sql
			expectIdle: 100,
		},
		{
			desc: "zero values",
			giveDBConfig: `
			max_open_conns = 0
			max_idle_conns = 0
			`,
			expectMaxOpenConns: 0,
			expectIdle:         0,
		},
		{
			desc: "custom values",
			giveDBConfig: `
			max_open_conns = 1000
			max_idle_conns = 50
			conn_max_lifetime = "10s"
			`,
			expectMaxOpenConns: 1000,
			expectIdle:         50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			dbPath := filepath.ToSlash(filepath.Join(t.TempDir(), "test-datastore-configure.sqlite3"))

			log, _ := test.NewNullLogger()
			p := New(log)
			err := p.Configure(ctx, fmt.Sprintf(`
				database_type = "sqlite3"
				log_sql = true
				connection_string = "%s"
				%s
			`, dbPath, tt.giveDBConfig))
			require.NoError(t, err)
			defer p.Close()

			db := p.db.DB.DB()
			require.Equal(t, tt.expectMaxOpenConns, db.Stats().MaxOpenConnections)

			// begin many queries simultaneously
			numQueries := 100
			var rowsList []*sql.Rows
			for range numQueries {
				rows, err := db.Query("SELECT * FROM bundles")
				require.NoError(t, err)
				rowsList = append(rowsList, rows)
			}

			// close all open queries, which results in idle connections
			for _, rows := range rowsList {
				require.NoError(t, rows.Close())
			}
			require.Equal(t, tt.expectIdle, db.Stats().Idle)
		})
	}
}

// removeDirWithRetry removes dir, retrying a few times on Windows where a
// closed SQLite file handle may not be released immediately. On other
// platforms a single RemoveAll always succeeds.
func removeDirWithRetry(t *testing.T, dir string) {
	const attempts = 20
	var err error
	for range attempts {
		if err = os.RemoveAll(dir); err == nil {
			return
		}
		if runtime.GOOS != "windows" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	assert.NoError(t, err, "failed to remove migration temp dir %q", dir)
}

func TestMigration(t *testing.T) {
	ds := newTestPlugin(t)

	// Use a dedicated directory instead of t.TempDir(): the migration DBs run
	// in WAL mode, and on Windows the SQLite file handle (plus its -wal/-shm
	// sidecars) is not always released synchronously when Close() returns.
	// t.TempDir()'s built-in RemoveAll fails hard on the first "file in use"
	// error, causing a flake; removeDirWithRetry retries instead.
	dir, err := os.MkdirTemp("", "migration")
	require.NoError(t, err)
	t.Cleanup(func() {
		// Close the plugin before removing the temp dir. Cleanups run LIFO, so
		// this runs before newTestPlugin's own ds.Close(); without it the last
		// migration DB is still open when we remove the dir, which fails on
		// Windows where an open file cannot be unlinked.
		ds.Close()
		removeDirWithRetry(t, dir)
	})

	for schemaVersion := range latestSchemaVersion {
		t.Run(fmt.Sprintf("migration_from_schema_version_%d", schemaVersion), func(t *testing.T) {
			require := require.New(t)
			dbName := fmt.Sprintf("v%d.sqlite3", schemaVersion)
			dbPath := filepath.ToSlash(filepath.Join(dir, "migration-"+dbName))
			if runtime.GOOS == "windows" {
				dbPath = "/" + dbPath
			}
			dbURI := fmt.Sprintf("file://%s", dbPath)

			minimalDB := func() string {
				previousMinor := codeVersion
				if codeVersion.Minor == 0 {
					previousMinor.Major--
				} else {
					previousMinor.Minor--
				}
				return fmt.Sprintf(`
					CREATE TABLE "migrations" ("id" integer primary key autoincrement, "version" integer,"code_version" varchar(255) );
					INSERT INTO migrations("version", "code_version") VALUES (%d,%q);
				`, schemaVersion, previousMinor)
			}

			prepareDB := func(migrationSupported bool) {
				dump := migrationDumps[schemaVersion]
				if migrationSupported {
					require.NotEmpty(dump, "no migration dump set up for schema version")
				} else {
					require.Empty(dump, "migration dump exists for unsupported schema version")
					dump = minimalDB()
				}
				dumpDB(t, dbPath, dump)
				err := ds.Configure(ctx, fmt.Sprintf(`
					database_type = "sqlite3"
					connection_string = %q
				`, dbURI))
				if migrationSupported {
					require.NoError(err)
				} else {
					require.EqualError(err, fmt.Sprintf("datastore-sql: migrating from schema version %d requires a previous SPIRE release; please follow the upgrade strategy at doc/upgrading.md", schemaVersion))
				}
			}
			switch schemaVersion {
			// All of these schema versions were migrated by previous versions
			// of SPIRE server and no longer have migration code.
			case 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22:
				prepareDB(false)
			case 23:
				// Migration from v23 to v24 adds agent_version column
				prepareDB(true)
			case 24:
				// Migration from v24 to v25 adds additional_attributes column
				prepareDB(true)
			default:
				t.Fatalf("no migration test added for schema version %d", schemaVersion)
			}
		})
	}
}
