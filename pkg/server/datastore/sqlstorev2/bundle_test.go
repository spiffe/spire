package sqlstorev2_test

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/datastore"
	v2 "github.com/spiffe/spire/pkg/server/datastore/sqlstorev2"
	"github.com/spiffe/spire/pkg/server/datastore/sqltest"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

// TestConcurrentAppendBundle checks that concurrent read-modify-write updates
// of one bundle do not lose each other's changes.
func TestConcurrentAppendBundle(t *testing.T) {
	ctx := context.Background()
	ds := newBundleTestPlugin(t)

	const trustDomain = "spiffe://concurrent.example.org"
	_, err := ds.CreateBundle(ctx, &common.Bundle{TrustDomainId: trustDomain})
	require.NoError(t, err)

	const n = 10
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Go(func() {
			_, err := ds.AppendBundle(ctx, &common.Bundle{
				TrustDomainId:  trustDomain,
				JwtSigningKeys: []*common.PublicKey{{Kid: fmt.Sprintf("kid-%d", i), PkixBytes: []byte{byte(i)}}},
			})
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	bundle, err := ds.FetchBundle(ctx, trustDomain)
	require.NoError(t, err)
	require.Len(t, bundle.JwtSigningKeys, n)
}

// newBundleTestPlugin returns a configured datastore on the external database
// when one is set, or on a SQLite file otherwise.
func newBundleTestPlugin(t *testing.T) *v2.Plugin {
	log, _ := test.NewNullLogger()

	var config string
	if v2.TestDialect != "" {
		sqltest.WipeDatabase(t, v2.TestDialect, v2.TestConnString)
		config = externalDBConfig()
	} else {
		config = "database_type = \"sqlite3\"\nconnection_string = \"" + filepath.ToSlash(filepath.Join(t.TempDir(), "spire.db")) + "\"\n"
	}
	ds := v2.New(log)
	require.NoError(t, ds.Configure(context.Background(), config))
	t.Cleanup(func() { require.NoError(t, ds.Close()) })
	return ds
}

// TestNoOpUpdates is a smoke test that re-applying identical values neither
// fails nor duplicates rows.
func TestNoOpUpdates(t *testing.T) {
	ctx := context.Background()
	ds := newBundleTestPlugin(t)

	t.Run("bundle", func(t *testing.T) {
		bundle := &common.Bundle{TrustDomainId: "spiffe://noop.example.org", RefreshHint: 60}
		_, err := ds.CreateBundle(ctx, bundle)
		require.NoError(t, err)

		_, err = ds.UpdateBundle(ctx, bundle, nil)
		require.NoError(t, err)

		count, err := ds.CountBundles(ctx)
		require.NoError(t, err)
		require.Equal(t, int32(1), count)

		fetched, err := ds.FetchBundle(ctx, bundle.TrustDomainId)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, bundle, fetched)
	})

	t.Run("ca_journal", func(t *testing.T) {
		journal, err := ds.SetCAJournal(ctx, &datastore.CAJournal{ActiveX509AuthorityID: "a", Data: []byte("data")})
		require.NoError(t, err)

		_, err = ds.SetCAJournal(ctx, journal)
		require.NoError(t, err)

		journals, err := ds.ListCAJournalsForTesting(ctx)
		require.NoError(t, err)
		require.Len(t, journals, 1)

		fetched, err := ds.FetchCAJournal(ctx, journal.ActiveX509AuthorityID)
		require.NoError(t, err)
		require.Equal(t, journal, fetched)
	})
}
