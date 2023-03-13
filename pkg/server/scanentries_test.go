package server

import (
	"context"
	"sort"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Use a page size of two for unit tests
	entryScanPageSize = 2
}

func TestScanForBadEntries(t *testing.T) {
	good1 := &common.RegistrationEntry{
		ParentId:  "spiffe://example.org/node",
		SpiffeId:  "spiffe://example.org/workload",
		Selectors: []*common.Selector{{Type: "one", Value: "1"}},
	}
	good2 := &common.RegistrationEntry{
		ParentId:  "spiffe://example.org/node",
		SpiffeId:  "spiffe://example.org/workload",
		Selectors: []*common.Selector{{Type: "two", Value: "2"}},
	}
	good3 := &common.RegistrationEntry{
		ParentId:  "spiffe://example.org/node",
		SpiffeId:  "spiffe://example.org/workload",
		Selectors: []*common.Selector{{Type: "three", Value: "3"}},
	}
	badParentID := &common.RegistrationEntry{
		ParentId:  "spiffe://example.org//node",
		SpiffeId:  "spiffe://example.org/workload",
		Selectors: []*common.Selector{{Type: "bad", Value: "parent-id"}},
	}
	badSpiffeID := &common.RegistrationEntry{
		ParentId:  "spiffe://example.org/node",
		SpiffeId:  "spiffe://example.org//workload",
		Selectors: []*common.Selector{{Type: "bad", Value: "spiffe-id"}},
	}

	for _, tt := range []struct {
		name          string
		entries       []*common.RegistrationEntry
		expectLogs    []spiretest.LogEntry
		expectEntries []*common.RegistrationEntry
		expectDeleted int
	}{
		{
			name:          "no entries",
			expectDeleted: 0,
		},
		{
			name:          "no bad entries",
			entries:       []*common.RegistrationEntry{good1, good2, good3},
			expectEntries: []*common.RegistrationEntry{good1, good2, good3},
			expectDeleted: 0,
		},
		{
			name:    "bad spiffe id",
			entries: []*common.RegistrationEntry{good1, good2, badSpiffeID, good3},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Deleting entry with invalid spiffeID",
					Data: logrus.Fields{
						"entry_id":  "SOME-ID",
						"error":     "path cannot contain empty segments",
						"parent_id": "spiffe://example.org/node",
						"spiffe_id": "spiffe://example.org//workload",
					},
				},
			},
			expectEntries: []*common.RegistrationEntry{good1, good2, good3},
			expectDeleted: 1,
		},
		{
			name:    "bad parent id",
			entries: []*common.RegistrationEntry{good1, good2, badParentID, good3},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Deleting entry with invalid parentID",
					Data: logrus.Fields{
						"entry_id":  "SOME-ID",
						"error":     "path cannot contain empty segments",
						"parent_id": "spiffe://example.org//node",
						"spiffe_id": "spiffe://example.org/workload",
					},
				},
			},
			expectEntries: []*common.RegistrationEntry{good1, good2, good3},
			expectDeleted: 1,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			log, logHook := test.NewNullLogger()
			metrics := fakemetrics.New()
			ds := fakedatastore.New(t)

			for i, entry := range tt.entries {
				entry, err := ds.CreateRegistrationEntry(context.Background(), entry)
				require.NoError(t, err)
				tt.entries[i].EntryId = entry.EntryId
				if i < len(tt.expectEntries) {
					tt.expectEntries[i].CreatedAt = entry.CreatedAt
				}
			}

			require.NoError(t, scanForBadEntries(log, metrics, ds)(context.Background()))

			resp, err := ds.ListRegistrationEntries(context.Background(), &datastore.ListRegistrationEntriesRequest{})
			require.NoError(t, err)

			sortEntries(tt.expectEntries)
			sortEntries(resp.Entries)
			spiretest.AssertProtoListEqual(t, tt.expectEntries, resp.Entries)

			// Assert the logs are as expected. The Entry IDs need to be
			// patched up in the log entries since they are non-deterministic.
			logEntries := logHook.AllEntries()
			for _, logEntry := range logEntries {
				if _, ok := logEntry.Data["entry_id"]; ok {
					logEntry.Data["entry_id"] = "SOME-ID"
				}
			}
			spiretest.AssertLogs(t, logEntries, tt.expectLogs)

			assert.Equal(t, []fakemetrics.MetricItem{
				{
					Type: fakemetrics.SetGaugeType,
					Key:  []string{"entry", "deleted"},
					Val:  float32(tt.expectDeleted),
				},
			}, metrics.AllMetrics())
		})
	}
}

func sortEntries(es []*common.RegistrationEntry) {
	sort.Slice(es, func(a, b int) bool {
		return es[a].EntryId < es[b].EntryId
	})
}
