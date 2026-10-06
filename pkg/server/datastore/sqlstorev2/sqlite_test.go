//go:build cgo

package sqlstorev2

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestSQLiteConnect(t *testing.T) {
	log, _ := test.NewNullLogger()
	cfg := &sqlcommon.Configuration{
		ConnectionString: sqlitePath(t),
		DBTypeConfig:     &sqlcommon.DBTypeConfig{DatabaseType: sqlcommon.SQLite},
	}
	db, version, supportsCTE, err := sqliteDB{log: log}.connect(context.Background(), cfg, false)
	require.NoError(t, err)
	require.NotNil(t, db)
	require.NotEmpty(t, version)
	require.True(t, supportsCTE)

	raw, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, raw.Close())
}

func TestConfigureSQLite(t *testing.T) {
	path := sqlitePath(t)
	ds := newSQLitePlugin(t)
	configure(t, ds, fmt.Sprintf(`
		database_type = "sqlite3"
		connection_string = %q
	`, path))

	var jm struct{ JournalMode string }
	require.NoError(t, ds.RawScan(&jm, "PRAGMA journal_mode"))
	require.Equal(t, "wal", jm.JournalMode)

	var fk struct{ ForeignKeys string }
	require.NoError(t, ds.RawScan(&fk, "PRAGMA foreign_keys"))
	require.Equal(t, "1", fk.ForeignKeys)
}

func TestConfigurePoolOptions(t *testing.T) {
	path := sqlitePath(t)

	ds := newSQLitePlugin(t)
	configure(t, ds, fmt.Sprintf(`
		database_type = "sqlite3"
		connection_string = %q
	`, path))
	require.Equal(t, 100, ds.db.raw.Stats().MaxOpenConnections)

	ds = newSQLitePlugin(t)
	configure(t, ds, fmt.Sprintf(`
		database_type = "sqlite3"
		connection_string = %q
		max_open_conns = 7
		max_idle_conns = 3
		conn_max_lifetime = "1m"
	`, path))
	require.Equal(t, 7, ds.db.raw.Stats().MaxOpenConnections)
}

func TestReconfigure(t *testing.T) {
	path := sqlitePath(t)
	otherPath := sqlitePath(t)

	log, hook := test.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)
	ds := New(log)
	t.Cleanup(func() { require.NoError(t, ds.Close()) })

	configure(t, ds, fmt.Sprintf(`
		database_type = "sqlite3"
		connection_string = %q
	`, path))
	first := ds.db
	var v int
	hook.Reset()
	require.NoError(t, ds.RawScan(&v, "SELECT 1"))
	require.False(t, loggedSQL(hook), "SQL logged with log_sql disabled")

	// Same connection string: the pool is kept and log_sql is applied.
	configure(t, ds, fmt.Sprintf(`
		database_type = "sqlite3"
		connection_string = %q
		log_sql = true
	`, path))
	require.Same(t, first.raw, ds.db.raw)
	hook.Reset()
	require.NoError(t, ds.RawScan(&v, "SELECT 1"))
	require.True(t, loggedSQL(hook), "SQL not logged with log_sql enabled")

	// New connection string: a new pool is opened and the old one closed.
	configure(t, ds, fmt.Sprintf(`
		database_type = "sqlite3"
		connection_string = %q
	`, otherPath))
	require.NotSame(t, first.raw, ds.db.raw)
	require.ErrorContains(t, first.raw.Ping(), "database is closed")
}

func TestReadOnlyConnection(t *testing.T) {
	path := sqlitePath(t)
	ds := newSQLitePlugin(t)
	configure(t, ds, fmt.Sprintf(`
		database_type = "sqlite3"
		connection_string = %q
		ro_connection_string = %q
	`, path, path))
	require.NotNil(t, ds.roDb)
	require.NotSame(t, ds.db.raw, ds.roDb.raw)
	ro := ds.roDb

	// Dropping ro_connection_string closes the read-only pool.
	configure(t, ds, fmt.Sprintf(`
		database_type = "sqlite3"
		connection_string = %q
	`, path))
	require.Nil(t, ds.roDb)
	require.ErrorContains(t, ro.raw.Ping(), "database is closed")
}

func TestFailedReconfigureKeepsConnections(t *testing.T) {
	path := sqlitePath(t)
	otherPath := sqlitePath(t)
	ds := newSQLitePlugin(t)
	configure(t, ds, fmt.Sprintf(`
		database_type = "sqlite3"
		connection_string = %q
	`, path))
	current := ds.db

	var opened []*gorm.DB
	ds.dialectFor = func(databaseType string, log logrus.FieldLogger) (dialect, error) {
		dia, err := newDialect(databaseType, log)
		return failReadOnlyDialect{dialect: dia, opened: &opened}, err
	}

	err := ds.Configure(context.Background(), fmt.Sprintf(`
		database_type = "sqlite3"
		connection_string = %q
		ro_connection_string = %q
	`, otherPath, otherPath))
	require.EqualError(t, err, "datastore-sql: read-only connection failed")

	require.Same(t, current, ds.db)
	require.NoError(t, ds.db.raw.Ping())
	require.Nil(t, ds.roDb)

	// The read-write pool opened for the rejected configuration is closed.
	require.Len(t, opened, 1)
	raw, err := opened[0].DB()
	require.NoError(t, err)
	require.ErrorContains(t, raw.Ping(), "database is closed")
}

func TestCloseResetsConnections(t *testing.T) {
	path := sqlitePath(t)
	log, _ := test.NewNullLogger()
	ds := New(log)
	configure(t, ds, fmt.Sprintf(`
		database_type = "sqlite3"
		connection_string = %q
		ro_connection_string = %q
	`, path, path))

	require.NoError(t, ds.Close())
	require.Nil(t, ds.db)
	require.Nil(t, ds.roDb)
	requireNotConfigured(t, ds)
	require.NoError(t, ds.Close())

	// Configuring again after Close opens a fresh pool.
	configure(t, ds, fmt.Sprintf(`
		database_type = "sqlite3"
		connection_string = %q
	`, path))
	var v int
	require.NoError(t, ds.RawScan(&v, "SELECT 1"))
	require.NoError(t, ds.Close())
}

// newSQLitePlugin returns a Plugin that is closed when the test ends. Tests
// call it after creating their database paths so the LIFO cleanup releases
// the file handles before t.TempDir removes the directory, which Windows
// requires.
func newSQLitePlugin(t *testing.T) *Plugin {
	log, _ := test.NewNullLogger()
	ds := New(log)
	t.Cleanup(func() { require.NoError(t, ds.Close()) })
	return ds
}

func sqlitePath(t *testing.T) string {
	return filepath.ToSlash(filepath.Join(t.TempDir(), "db.sqlite3"))
}

func configure(t *testing.T, ds *Plugin, config string) {
	t.Helper()
	require.NoError(t, ds.Configure(context.Background(), config))
}

func loggedSQL(hook *test.Hook) bool {
	for _, entry := range hook.AllEntries() {
		if entry.Data[telemetry.SubsystemName] == "gorm" {
			return true
		}
	}
	return false
}

// failReadOnlyDialect fails every read-only connect and records the
// read-write connections it opens.
type failReadOnlyDialect struct {
	dialect
	opened *[]*gorm.DB
}

func (d failReadOnlyDialect) connect(ctx context.Context, cfg *sqlcommon.Configuration, isReadOnly bool) (*gorm.DB, string, bool, error) {
	if isReadOnly {
		return nil, "", false, errors.New("read-only connection failed")
	}
	db, version, supportsCTE, err := d.dialect.connect(ctx, cfg, isReadOnly)
	if err == nil {
		*d.opened = append(*d.opened, db)
	}
	return db, version, supportsCTE, err
}
