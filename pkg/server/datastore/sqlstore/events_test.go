package sqlstore

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/stretchr/testify/require"
)

func TestFetchChangesCancellationDoesNotAdvanceTracker(t *testing.T) {
	ds := newTestPlugin(t)
	require.NoError(t, ds.CreateRegistrationEntryEventForTesting(context.Background(), &datastore.RegistrationEntryEvent{
		EventID: 1,
		EntryID: "entry",
	}))

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ds.FetchRegistrationEntryChanges(canceled, &datastore.FetchRegistrationEntryChangesRequest{EventTimeout: time.Minute})
	require.ErrorIs(t, err, context.Canceled)

	resp, err := ds.FetchRegistrationEntryChanges(context.Background(), &datastore.FetchRegistrationEntryChangesRequest{EventTimeout: time.Minute})
	require.NoError(t, err)
	require.Equal(t, []string{"entry"}, resp.EntryIDs)
}

func TestFetchChangesExpiresGap(t *testing.T) {
	ds := newTestPlugin(t)
	now := time.Now()
	ds.now = func() time.Time { return now }

	require.NoError(t, ds.CreateAttestedNodeEventForTesting(context.Background(), &datastore.AttestedNodeEvent{EventID: 1, SpiffeID: "one"}))
	_, err := ds.FetchAttestedNodeChanges(context.Background(), &datastore.FetchAttestedNodeChangesRequest{EventTimeout: time.Minute})
	require.NoError(t, err)
	require.NoError(t, ds.CreateAttestedNodeEventForTesting(context.Background(), &datastore.AttestedNodeEvent{EventID: 3, SpiffeID: "three"}))
	resp, err := ds.FetchAttestedNodeChanges(context.Background(), &datastore.FetchAttestedNodeChangesRequest{EventTimeout: time.Minute})
	require.NoError(t, err)
	require.Equal(t, int32(1), resp.PendingEvents)

	now = now.Add(time.Minute)
	require.NoError(t, ds.CreateAttestedNodeEventForTesting(context.Background(), &datastore.AttestedNodeEvent{EventID: 2, SpiffeID: "two"}))
	resp, err = ds.FetchAttestedNodeChanges(context.Background(), &datastore.FetchAttestedNodeChangesRequest{EventTimeout: time.Minute})
	require.NoError(t, err)
	require.Empty(t, resp.SpiffeIDs)
	require.Zero(t, resp.PendingEvents)
}

func TestFetchChangesConcurrentCallsDeduplicate(t *testing.T) {
	ds := newTestPlugin(t)
	for eventID := uint(1); eventID <= 10; eventID++ {
		require.NoError(t, ds.CreateRegistrationEntryEventForTesting(context.Background(), &datastore.RegistrationEntryEvent{
			EventID: eventID,
			EntryID: "entry",
		}))
	}

	var wg sync.WaitGroup
	results := make(chan []string, 20)
	for range 20 {
		wg.Go(func() {
			resp, err := ds.FetchRegistrationEntryChanges(context.Background(), &datastore.FetchRegistrationEntryChangesRequest{EventTimeout: time.Minute})
			require.NoError(t, err)
			results <- resp.EntryIDs
		})
	}
	wg.Wait()
	close(results)

	var keys []string
	for result := range results {
		keys = append(keys, result...)
	}
	require.Equal(t, []string{"entry"}, keys)
}

func TestFetchChangeStreamsAreIndependent(t *testing.T) {
	ds := newTestPlugin(t)
	ds.registrationEntryChanges.mu.Lock()
	locked := true
	defer func() {
		if locked {
			ds.registrationEntryChanges.mu.Unlock()
		}
	}()

	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		_, err := ds.FetchRegistrationEntryChanges(context.Background(), &datastore.FetchRegistrationEntryChangesRequest{EventTimeout: time.Minute})
		done <- err
	}()
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := ds.FetchAttestedNodeChanges(ctx, &datastore.FetchAttestedNodeChangesRequest{EventTimeout: time.Minute})
	require.NoError(t, err)

	ds.registrationEntryChanges.mu.Unlock()
	locked = false
	require.NoError(t, <-done)
}

func TestFetchChangesUsesReplicaOnlyForForwardScan(t *testing.T) {
	primary := newTestPlugin(t)
	replica := newTestPlugin(t)
	primary.roDb = replica.db

	require.NoError(t, primary.CreateRegistrationEntryEventForTesting(context.Background(), &datastore.RegistrationEntryEvent{EventID: 1, EntryID: "primary-startup"}))
	require.NoError(t, replica.CreateRegistrationEntryEventForTesting(context.Background(), &datastore.RegistrationEntryEvent{EventID: 2, EntryID: "replica"}))

	resp, err := primary.FetchRegistrationEntryChanges(context.Background(), &datastore.FetchRegistrationEntryChangesRequest{EventTimeout: time.Minute})
	require.NoError(t, err)
	require.Equal(t, []string{"replica"}, resp.EntryIDs)

	// Lower-ID startup backfill is resolved against the primary.
	resp, err = primary.FetchRegistrationEntryChanges(context.Background(), &datastore.FetchRegistrationEntryChangesRequest{EventTimeout: time.Minute})
	require.NoError(t, err)
	require.Equal(t, []string{"primary-startup"}, resp.EntryIDs)

	require.NoError(t, primary.CreateRegistrationEntryEventForTesting(context.Background(), &datastore.RegistrationEntryEvent{EventID: 3, EntryID: "primary-gap"}))
	require.NoError(t, replica.CreateRegistrationEntryEventForTesting(context.Background(), &datastore.RegistrationEntryEvent{EventID: 4, EntryID: "replica-next"}))
	resp, err = primary.FetchRegistrationEntryChanges(context.Background(), &datastore.FetchRegistrationEntryChangesRequest{EventTimeout: time.Minute})
	require.NoError(t, err)
	require.Equal(t, []string{"replica-next"}, resp.EntryIDs)
	require.Equal(t, int32(1), resp.PendingEvents)

	// Missing IDs are also resolved against the primary.
	resp, err = primary.FetchRegistrationEntryChanges(context.Background(), &datastore.FetchRegistrationEntryChangesRequest{EventTimeout: time.Minute})
	require.NoError(t, err)
	require.Equal(t, []string{"primary-gap"}, resp.EntryIDs)
	require.Zero(t, resp.PendingEvents)
}

func TestConfigureResetsTrackersOnlyOnSuccess(t *testing.T) {
	// Register the temporary directory cleanup before closing the datastore so
	// the SQLite file is not still open when Windows removes the directory.
	tempDir := t.TempDir()
	log, _ := test.NewNullLogger()
	ds := New(log)
	t.Cleanup(func() { ds.Close() })
	dbPath := filepath.ToSlash(filepath.Join(tempDir, "events.sqlite3"))
	configuration := fmt.Sprintf(`database_type = "sqlite3"
connection_string = %q`, dbPath)
	require.NoError(t, ds.Configure(context.Background(), configuration))
	require.NoError(t, ds.CreateRegistrationEntryEventForTesting(context.Background(), &datastore.RegistrationEntryEvent{EventID: 1, EntryID: "one"}))

	resp, err := ds.FetchRegistrationEntryChanges(context.Background(), &datastore.FetchRegistrationEntryChangesRequest{EventTimeout: time.Minute})
	require.NoError(t, err)
	require.Equal(t, []string{"one"}, resp.EntryIDs)

	require.Error(t, ds.Configure(context.Background(), `database_type = "invalid"`))
	resp, err = ds.FetchRegistrationEntryChanges(context.Background(), &datastore.FetchRegistrationEntryChangesRequest{EventTimeout: time.Minute})
	require.NoError(t, err)
	require.Empty(t, resp.EntryIDs)

	require.NoError(t, ds.Configure(context.Background(), configuration))
	resp, err = ds.FetchRegistrationEntryChanges(context.Background(), &datastore.FetchRegistrationEntryChangesRequest{EventTimeout: time.Minute})
	require.NoError(t, err)
	require.Equal(t, []string{"one"}, resp.EntryIDs)
}

func TestPruneEventsIsAtomic(t *testing.T) {
	ds := newTestPlugin(t)
	require.NoError(t, ds.CreateRegistrationEntryEventForTesting(context.Background(), &datastore.RegistrationEntryEvent{EventID: 1, EntryID: "entry"}))
	require.NoError(t, ds.CreateAttestedNodeEventForTesting(context.Background(), &datastore.AttestedNodeEvent{EventID: 1, SpiffeID: "node"}))
	require.NoError(t, ds.RawExec(`CREATE TRIGGER fail_node_event_delete BEFORE DELETE ON attested_node_entries_events BEGIN SELECT RAISE(ABORT, 'fail'); END`))

	err := ds.PruneEvents(context.Background(), &datastore.PruneEventsRequest{OlderThan: -time.Hour})
	require.Error(t, err)

	var entryEvents, nodeEvents int
	require.NoError(t, ds.db.Raw("SELECT COUNT(*) FROM registered_entries_events").Row().Scan(&entryEvents))
	require.NoError(t, ds.db.Raw("SELECT COUNT(*) FROM attested_node_entries_events").Row().Scan(&nodeEvents))
	require.Equal(t, 1, entryEvents)
	require.Equal(t, 1, nodeEvents)
}
