package sqlstorev2_test

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/datastore"
	v2 "github.com/spiffe/spire/pkg/server/datastore/sqlstorev2"
	"github.com/spiffe/spire/pkg/server/datastore/sqltest"
	"github.com/stretchr/testify/require"
)

func TestDisableMigrationAllowsCAJournalWritesOnPreviousSchema(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.ToSlash(filepath.Join(t.TempDir(), "v25.sqlite3"))
	if runtime.GOOS == "windows" {
		dbPath = "/" + dbPath
	}
	db, err := sql.Open("sqlite3", dbPath)
	require.NoError(t, err)
	_, err = db.Exec(sqltest.MigrationDumps[25])
	require.NoError(t, err)
	require.NoError(t, db.Close())

	log, _ := test.NewNullLogger()
	ds := v2.New(log)
	t.Cleanup(func() {
		require.NoError(t, ds.Close())
	})

	err = ds.Configure(ctx, fmt.Sprintf(`
		database_type = "sqlite3"
		connection_string = %q
		disable_migration = true
	`, "file://"+dbPath))
	require.NoError(t, err)

	caJournals, err := ds.ListCAJournalsForTesting(ctx)
	require.NoError(t, err)
	require.Len(t, caJournals, 1)

	caJournals[0].Data = []byte("updated")
	updated, err := ds.SetCAJournal(ctx, caJournals[0])
	require.NoError(t, err)
	require.Equal(t, caJournals[0], updated)

	created, err := ds.SetCAJournal(ctx, &datastore.CAJournal{
		Data:                  []byte("created"),
		ActiveX509AuthorityID: "new-authority",
	})
	require.NoError(t, err)
	require.NotZero(t, created.ID)

	fetched, err := ds.FetchCAJournal(ctx, "new-authority")
	require.NoError(t, err)
	require.Equal(t, created, fetched)

	// Re-setting an identical journal must not fail or duplicate the row.
	again, err := ds.SetCAJournal(ctx, created)
	require.NoError(t, err)
	require.Equal(t, created, again)

	caJournals, err = ds.ListCAJournalsForTesting(ctx)
	require.NoError(t, err)
	require.Len(t, caJournals, 2)
}
