package sqlstorev2

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"github.com/stretchr/testify/require"
)

func TestNewAndClose(t *testing.T) {
	log, _ := test.NewNullLogger()
	ds := New(log)
	require.NotNil(t, ds)
	// Close with no open connections must be a clean no-op.
	require.NoError(t, ds.Close())
}

func TestPluginName(t *testing.T) {
	require.Equal(t, "sql_v2", PluginName)
}

func TestSQLiteConnect(t *testing.T) {
	log, _ := test.NewNullLogger()
	cfg := &sqlcommon.Configuration{
		ConnectionString: filepath.ToSlash(filepath.Join(t.TempDir(), "db.sqlite3")),
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

func TestAWSPostgresDSN(t *testing.T) {
	// pgx.ParseConfig merges libpq env fallbacks (PGPASSWORD); isolate so the
	// connection string alone drives the password check, as awsrds_test.go does.
	t.Setenv("PGPASSWORD", "")

	cfg := &sqlcommon.Configuration{
		ConnectionString: "postgres://dbuser@my-instance.rds.amazonaws.com:5432/spire",
		DBTypeConfig: &sqlcommon.DBTypeConfig{
			DatabaseType: sqlcommon.AWSPostgreSQL,
			AWSPostgres: &sqlcommon.AWSConfig{
				Region:          "us-west-2",
				AccessKeyID:     "AKID",
				SecretAccessKey: "SECRET",
			},
		},
	}
	dsn, err := sqlcommon.BuildAWSPostgresDSN(cfg)
	require.NoError(t, err)
	require.Contains(t, dsn, "my-instance.rds.amazonaws.com:5432")
}

func TestAWSPostgresRejectsPassword(t *testing.T) {
	t.Setenv("PGPASSWORD", "")

	cfg := &sqlcommon.Configuration{
		ConnectionString: "postgres://dbuser:secret@host:5432/spire",
		DBTypeConfig: &sqlcommon.DBTypeConfig{
			DatabaseType: sqlcommon.AWSPostgreSQL,
			AWSPostgres:  &sqlcommon.AWSConfig{Region: "us-west-2"},
		},
	}
	_, err := sqlcommon.BuildAWSPostgresDSN(cfg)
	require.ErrorContains(t, err, "password should not be set when using IAM authentication")
}

func TestConfigureSQLite(t *testing.T) {
	log, _ := test.NewNullLogger()
	ds := New(log)

	dir := t.TempDir()
	// Register Close AFTER TempDir so LIFO cleanup releases the DB file
	// handle before RemoveAll (avoids a Windows "file in use" failure).
	t.Cleanup(func() { require.NoError(t, ds.Close()) })

	dbPath := filepath.ToSlash(filepath.Join(dir, "db.sqlite3"))
	err := ds.Configure(context.Background(), fmt.Sprintf(`
		database_type = "sqlite3"
		log_sql = true
		connection_string = "%s"
	`, dbPath))
	require.NoError(t, err)

	var jm struct{ JournalMode string }
	require.NoError(t, ds.RawScan(&jm, "PRAGMA journal_mode"))
	require.Equal(t, "wal", jm.JournalMode)

	var fk struct{ ForeignKeys string }
	require.NoError(t, ds.RawScan(&fk, "PRAGMA foreign_keys"))
	require.Equal(t, "1", fk.ForeignKeys)
}
