package sqlstorev2_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

var (
	ddlPrefix = regexp.MustCompile(`(?i)^\s*(ALTER|CREATE|DROP|RENAME)\s`)

	// additiveDDL matches statements that add a column or an index. The
	// column name must be quoted, which excludes ADD CONSTRAINT and friends.
	additiveDDL = regexp.MustCompile("(?i)^\\s*(ALTER TABLE \\S+ ADD (COLUMN )?[`\"]|CREATE (UNIQUE )?INDEX )")

	migrationUpdate = regexp.MustCompile("(?i)^\\s*UPDATE [`\"]?migrations[`\"]? ")
)

// sqlLogger returns a logger that captures the SQL statements a datastore
// configured with log_sql = true logs at debug level.
func sqlLogger() (*logrus.Logger, *test.Hook) {
	log, hook := test.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)
	return log, hook
}

// requireMigrationRecorded fails unless an UPDATE of the migrations table was
// captured, which proves the SQL statements were logged.
func requireMigrationRecorded(t *testing.T, hook *test.Hook) {
	t.Helper()
	for _, entry := range hook.AllEntries() {
		if migrationUpdate.MatchString(entry.Message) {
			return
		}
	}
	require.Fail(t, "no UPDATE of the migrations table was logged")
}

// requireOnlyAdditiveDDL fails if any captured statement changes the schema
// other than by adding a column or an index.
func requireOnlyAdditiveDDL(t *testing.T, hook *test.Hook) {
	t.Helper()
	var unexpected []string
	for _, entry := range hook.AllEntries() {
		if ddlPrefix.MatchString(entry.Message) && !additiveDDL.MatchString(entry.Message) {
			unexpected = append(unexpected, strings.TrimSpace(entry.Message))
		}
	}
	require.Empty(t, unexpected, "upgrade must only add columns and indexes")
}

// requireNoDDL fails if any captured statement changes the schema.
func requireNoDDL(t *testing.T, hook *test.Hook) {
	t.Helper()
	var ddl []string
	for _, entry := range hook.AllEntries() {
		if ddlPrefix.MatchString(entry.Message) {
			ddl = append(ddl, strings.TrimSpace(entry.Message))
		}
	}
	require.Empty(t, ddl, "no schema change expected")
}
