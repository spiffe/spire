package sqlstorev2_test

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	v1 "github.com/spiffe/spire/pkg/server/datastore/sqlstore"
	v2 "github.com/spiffe/spire/pkg/server/datastore/sqlstorev2"
	"github.com/spiffe/spire/pkg/server/datastore/sqltest"
	"github.com/stretchr/testify/require"
)

func TestSchemaParityV1V2ExternalDB(t *testing.T) {
	requireExternalDB(t)
	log, _ := test.NewNullLogger()

	sqltest.WipeDatabase(t, v2.TestDialect, v2.TestConnString)
	configureAndClose(t, v1.New(log), externalDBConfig())
	v1Schema := describeExternalSchema(t)

	sqltest.WipeDatabase(t, v2.TestDialect, v2.TestConnString)
	configureAndClose(t, v2.New(log), externalDBConfig())
	v2Schema := describeExternalSchema(t)

	require.NotEmpty(t, v1Schema)
	require.Equal(t, v1Schema, v2Schema, "v2 %s schema must be identical to v1", v2.TestDialect)
}

func TestUpgradeExternalDB(t *testing.T) {
	requireExternalDB(t)

	// The columns each schema version added, which are dropped to revert a
	// database to an older version.
	addedColumns := map[int]string{
		24: "ALTER TABLE attested_node_entries DROP COLUMN agent_version",
		25: "ALTER TABLE registered_entries DROP COLUMN additional_attributes",
		26: "ALTER TABLE ca_journals DROP COLUMN journal_id",
		27: "ALTER TABLE registered_entries DROP COLUMN wit_svid_ttl",
	}

	for from := v2.LastMinorReleaseSchemaVersion; from < v2.LatestSchemaVersion; from++ {
		t.Run(fmt.Sprintf("from_schema_version_%d", from), func(t *testing.T) {
			log, _ := test.NewNullLogger()
			sqltest.WipeDatabase(t, v2.TestDialect, v2.TestConnString)
			configureAndClose(t, v1.New(log), externalDBConfig())
			want := describeExternalSchema(t)
			db := openExternalDB(t)
			var wantVersion int
			require.NoError(t, db.QueryRow("SELECT version FROM migrations").Scan(&wantVersion))

			var stmts []string
			for version := from + 1; version <= v2.LatestSchemaVersion; version++ {
				stmt, ok := addedColumns[version]
				require.True(t, ok, "no statement reverting schema version %d", version)
				stmts = append(stmts, stmt)
			}
			stmts = append(stmts,
				fmt.Sprintf("UPDATE migrations SET version = %d", from),
				"INSERT INTO attested_node_entries (spiffe_id) VALUES ('spiffe://example.org/agent')",
				"INSERT INTO registered_entries (entry_id, spiffe_id, parent_id) VALUES ('entry', 'spiffe://example.org/workload', 'spiffe://example.org/agent')",
				// Several journals, so the unique index on journal_id is built
				// over more than one NULL.
				"INSERT INTO ca_journals (active_x509_authority_id) VALUES ('a')",
				"INSERT INTO ca_journals (active_x509_authority_id) VALUES ('b')",
				"INSERT INTO ca_journals (active_x509_authority_id) VALUES ('c')",
			)
			for _, stmt := range stmts {
				_, err := db.Exec(stmt)
				require.NoError(t, err, stmt)
			}
			rowsBefore := externalRowCounts(t, db)

			upgrade := func() *test.Hook {
				v2Log, hook := sqlLogger()
				configureAndClose(t, v2.New(v2Log), externalDBConfig()+"log_sql = true\n")
				requireMigrationRecorded(t, hook)
				require.Equal(t, want, describeExternalSchema(t))
				var version int
				require.NoError(t, db.QueryRow("SELECT version FROM migrations").Scan(&version))
				require.Equal(t, wantVersion, version)
				require.Equal(t, rowsBefore, externalRowCounts(t, db))
				return hook
			}

			requireOnlyAdditiveDDL(t, upgrade())

			// Steps whose changes are already applied run again without DDL.
			_, err := db.Exec(fmt.Sprintf("UPDATE migrations SET version = %d", from))
			require.NoError(t, err)
			requireNoDDL(t, upgrade())
		})
	}
}

func TestResumePartialInitializationExternalDB(t *testing.T) {
	requireExternalDB(t)
	log, _ := test.NewNullLogger()

	sqltest.WipeDatabase(t, v2.TestDialect, v2.TestConnString)
	configureAndClose(t, v2.New(log), externalDBConfig())
	want := describeExternalSchema(t)

	db := openExternalDB(t)
	for _, stmt := range []string{"DELETE FROM migrations", "DROP TABLE ca_journals"} {
		_, err := db.Exec(stmt)
		require.NoError(t, err)
	}

	ds := v2.New(log)
	if v2.TestDialect == "postgres" {
		require.ErrorContains(t, ds.Configure(context.Background(), externalDBConfig()), "migrations table has no row")
		return
	}
	require.ErrorContains(t, ds.Configure(context.Background(), externalDBConfig()+"disable_migration = true\n"),
		"database initialization did not complete")
	require.NoError(t, ds.Configure(context.Background(), externalDBConfig()))
	require.NoError(t, ds.Close())

	require.Equal(t, want, describeExternalSchema(t))
	var rows int
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM migrations").Scan(&rows))
	require.Equal(t, 1, rows)
}

func TestNoCurrentSchemaExternalDB(t *testing.T) {
	requireExternalDB(t)
	log, _ := test.NewNullLogger()
	sqltest.WipeDatabase(t, v2.TestDialect, v2.TestConnString)

	connString := strings.Replace(v2.TestConnString, "/spire?", "/?", 1)
	if v2.TestDialect == "postgres" {
		connString += "&search_path="
	}
	require.NotEqual(t, v2.TestConnString, connString)

	ds := v2.New(log)
	err := ds.Configure(context.Background(), fmt.Sprintf("database_type = %q\nconnection_string = %q\n", v2.TestDialect, connString))
	require.ErrorContains(t, err, "no current database or schema is selected")
}

// externalRowCounts returns the number of rows in each table of the external
// database.
func externalRowCounts(t *testing.T, db *sql.DB) map[string]int {
	t.Helper()
	query := "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()"
	if v2.TestDialect == "postgres" {
		query = "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()"
	}
	rows, err := db.Query(query)
	require.NoError(t, err)
	var tables []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		tables = append(tables, name)
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())

	counts := make(map[string]int)
	for _, table := range tables {
		var n int
		require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM "+table).Scan(&n))
		counts[table] = n
	}
	return counts
}

func openExternalDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open(v2.TestDialect, v2.TestConnString)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

// describeExternalSchema returns a canonical description of every table,
// column, index and constraint in the external database.
func describeExternalSchema(t *testing.T) string {
	t.Helper()
	var queries []string
	switch v2.TestDialect {
	case "postgres":
		queries = []string{
			`SELECT table_name, column_name, data_type, coalesce(character_maximum_length::text, ''), is_nullable, coalesce(column_default, '')
			FROM information_schema.columns WHERE table_schema = current_schema() ORDER BY 1, 2`,
			// The index name is dropped from the definition so that it is
			// compared once, in its own column.
			`SELECT tablename, indexname, regexp_replace(indexdef, '^CREATE (UNIQUE )?INDEX \S+', 'CREATE \1INDEX')
			FROM pg_indexes WHERE schemaname = current_schema() ORDER BY 1, 2`,
			`SELECT table_name, constraint_name, constraint_type
			FROM information_schema.table_constraints WHERE table_schema = current_schema() AND constraint_type <> 'CHECK' ORDER BY 1, 2`,
		}
	case "mysql":
		queries = []string{
			`SELECT table_name, engine, table_collation, row_format
			FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY 1`,
			`SELECT table_name, column_name, column_type, is_nullable, coalesce(column_default, ''), column_key, extra,
				coalesce(character_set_name, ''), coalesce(collation_name, '')
			FROM information_schema.columns WHERE table_schema = DATABASE() ORDER BY 1, 2`,
			`SELECT table_name, index_name, non_unique, group_concat(column_name ORDER BY seq_in_index)
			FROM information_schema.statistics WHERE table_schema = DATABASE() GROUP BY 1, 2, 3 ORDER BY 1, 2`,
			`SELECT table_name, constraint_name, constraint_type
			FROM information_schema.table_constraints WHERE table_schema = DATABASE() ORDER BY 1, 2`,
		}
	default:
		t.Fatalf("unsupported dialect %q", v2.TestDialect)
	}

	db := openExternalDB(t)
	var b strings.Builder
	for _, query := range queries {
		rows, err := db.Query(query)
		require.NoError(t, err)
		cols, err := rows.Columns()
		require.NoError(t, err)
		for rows.Next() {
			vals := make([]sql.NullString, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			require.NoError(t, rows.Scan(ptrs...))
			parts := make([]string, len(vals))
			for i, v := range vals {
				parts[i] = v.String
			}
			b.WriteString(strings.Join(parts, "|") + "\n")
		}
		require.NoError(t, rows.Err())
		require.NoError(t, rows.Close())
	}
	return b.String()
}

// requireExternalDB skips the test unless the integration harness linked in
// a MySQL or PostgreSQL database. The harness selects tests by the
// "ExternalDB" suffix, so a test named otherwise would never run there.
func requireExternalDB(t *testing.T) {
	t.Helper()
	require.True(t, strings.HasSuffix(t.Name(), "ExternalDB"), "external database tests must be named *ExternalDB")
	if v2.TestDialect == "" {
		t.Skip("no external database configured")
	}
}

func externalDBConfig() string {
	return fmt.Sprintf("database_type = %q\nconnection_string = %q\n", v2.TestDialect, v2.TestConnString)
}

func configureAndClose(t *testing.T, ds configurer, hcl string) {
	t.Helper()
	require.NoError(t, ds.Configure(context.Background(), hcl))
	require.NoError(t, ds.Close())
}
