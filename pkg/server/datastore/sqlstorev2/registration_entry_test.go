package sqlstorev2

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// TestEntryReadsAcrossChunks covers fetches of more than 10 ids and reads
// split into several statements, which the shared suite's few entries never
// reach.
func TestEntryReadsAcrossChunks(t *testing.T) {
	old := entryFetchChunk
	entryFetchChunk = 3
	t.Cleanup(func() { entryFetchChunk = old })

	ds := newNodeTestPlugin(t)
	ctx := context.Background()
	_, err := ds.CreateBundle(ctx, &common.Bundle{TrustDomainId: "spiffe://other.org"})
	require.NoError(t, err)

	const parent = "spiffe://example.org/agent"
	var created []*common.RegistrationEntry
	var ids []string
	for i := range 12 {
		entry, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
			ParentId:      parent,
			SpiffeId:      fmt.Sprintf("spiffe://example.org/w%02d", i),
			Selectors:     []*common.Selector{{Type: "a", Value: fmt.Sprint(i)}, {Type: "b", Value: "x"}},
			DnsNames:      []string{fmt.Sprintf("w%02d.example.org", i)},
			FederatesWith: []string{"spiffe://other.org"},
		})
		require.NoError(t, err)
		created = append(created, entry)
		ids = append(ids, entry.EntryId)
	}

	fetched, err := ds.FetchRegistrationEntries(ctx, ids)
	require.NoError(t, err)
	require.Len(t, fetched, len(created))
	for _, e := range created {
		require.True(t, proto.Equal(e, fetched[e.EntryId]), "fetched %v, want %v", fetched[e.EntryId], e)
	}

	// Text order of these values (0, 1, 10, 11, 2, …) differs from id order.
	var each []*common.Selector
	for i := range created {
		each = append(each, &common.Selector{Type: "a", Value: fmt.Sprint(i)})
	}
	for name, req := range map[string]*datastore.ListRegistrationEntriesRequest{
		"match any":        {BySelectors: &datastore.BySelectors{Match: datastore.MatchAny, Selectors: each}},
		"unfiltered":       {},
		"by parent":        {ByParentID: parent},
		"by selector":      {BySelectors: &datastore.BySelectors{Match: datastore.Superset, Selectors: []*common.Selector{{Type: "b", Value: "x"}}}},
		"by federatesWith": {ByFederatesWith: &datastore.ByFederatesWith{Match: datastore.MatchAny, TrustDomains: []string{"spiffe://other.org"}}},
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := ds.ListRegistrationEntries(ctx, req)
			require.NoError(t, err)
			require.Len(t, resp.Entries, len(created))
			for i, e := range created {
				require.True(t, proto.Equal(e, resp.Entries[i]), "entry %d: got %v, want %v", i, resp.Entries[i], e)
			}
		})
	}

	// Prune the first 7.
	require.NoError(t, ds.RawExec("UPDATE registered_entries SET expiry = 1 WHERE spiffe_id < 'spiffe://example.org/w07'"))
	before, err := ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{})
	require.NoError(t, err)
	require.NoError(t, ds.PruneRegistrationEntries(ctx, time.Now()))

	resp, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Entries, 5)
	require.Equal(t, created[7].EntryId, resp.Entries[0].EntryId)

	after, err := ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{
		GreaterThanEventID: before.Events[len(before.Events)-1].EventID,
	})
	require.NoError(t, err)
	var pruned []string
	for _, e := range after.Events {
		pruned = append(pruned, e.EntryID)
	}
	require.ElementsMatch(t, ids[:7], pruned)

	var children int64
	require.NoError(t, ds.db.Model(&Selector{}).Count(&children).Error)
	require.EqualValues(t, 10, children, "pruned entries' selectors are deleted")
}
