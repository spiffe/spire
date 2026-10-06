package sqlstorev2

import (
	"context"
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

func TestNewDialect(t *testing.T) {
	log, _ := test.NewNullLogger()

	for _, tt := range []struct {
		databaseType string
		expected     dialect
	}{
		{databaseType: sqlcommon.SQLite, expected: sqliteDB{log: log}},
		{databaseType: sqlcommon.PostgreSQL, expected: postgresDB{}},
		{databaseType: sqlcommon.AWSPostgreSQL, expected: postgresDB{}},
		{databaseType: sqlcommon.AzurePostgreSQL, expected: postgresDB{}},
		{databaseType: sqlcommon.MySQL, expected: mysqlDB{log: log}},
		{databaseType: sqlcommon.AWSMySQL, expected: mysqlDB{log: log}},
		{databaseType: sqlcommon.AzureMySQL, expected: mysqlDB{log: log}},
	} {
		t.Run(tt.databaseType, func(t *testing.T) {
			dia, err := newDialect(tt.databaseType, log)
			require.NoError(t, err)
			require.Equal(t, tt.expected, dia)
		})
	}

	_, err := newDialect("unknown", log)
	require.EqualError(t, err, "datastore-sql: unsupported database_type: unknown")
}

func TestConfigureAzureRejectsPassword(t *testing.T) {
	isolatePostgresEnv(t)

	for _, tt := range []struct {
		name   string
		config string
		err    string
	}{
		{
			name: "azure_postgres",
			config: `
				database_type "azure_postgres" {
					auth_type = "system_managed_identity"
				}
				connection_string = "postgres://dbuser:secret@host:5432/spire"
			`,
			err: "datastore-sql: invalid postgres configuration: password should not be set when using Microsoft Entra ID authentication",
		},
		{
			name: "azure_mysql",
			config: `
				database_type "azure_mysql" {
					auth_type = "system_managed_identity"
				}
				connection_string = "dbuser:secret@tcp(host:3306)/spire?parseTime=true"
			`,
			err: "datastore-sql: invalid mysql configuration: password should not be set when using Microsoft Entra ID authentication",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			log, _ := test.NewNullLogger()
			ds := New(log)
			require.EqualError(t, ds.Configure(context.Background(), tt.config), tt.err)
			requireNotConfigured(t, ds)
		})
	}
}

func TestConfigureInvalidConnMaxLifetime(t *testing.T) {
	log, _ := test.NewNullLogger()
	ds := New(log)

	// The duration is rejected before any connection is attempted, so the
	// unreachable host is never dialed.
	err := ds.Configure(context.Background(), `
		database_type = "postgres"
		connection_string = "postgres://dbuser@unreachable.invalid:5432/spire"
		conn_max_lifetime = "not-a-duration"
	`)
	require.ErrorContains(t, err, `failed to parse conn_max_lifetime "not-a-duration"`)
	requireNotConfigured(t, ds)
}

func TestRawScanNotConfigured(t *testing.T) {
	log, _ := test.NewNullLogger()
	requireNotConfigured(t, New(log))
}

func requireNotConfigured(t *testing.T, ds *Plugin) {
	t.Helper()
	var v int
	require.EqualError(t, ds.RawScan(&v, "SELECT 1"), "datastore-sql: datastore is not configured")
}

// isolatePostgresEnv keeps the developer's libpq environment out of the test:
// pgx.ParseConfig falls back to PGPASSWORD and the passfile for a password.
func isolatePostgresEnv(t *testing.T) {
	t.Setenv("PGPASSWORD", "")
	t.Setenv("PGPASSFILE", filepath.Join(t.TempDir(), "nonexistent"))
}
