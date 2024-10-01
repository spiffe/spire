package endpoints

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/require"
	/*
	   "github.com/spiffe/go-spiffe/v2/spiffeid"
	   "github.com/spiffe/spire/pkg/common/idutil"
	*/)

var (
	NodeAliasesByEntryID  = []string{telemetry.Entry, telemetry.NodeAliasesByEntryIDCache, telemetry.Count}
	NodeAliasesBySelector = []string{telemetry.Entry, telemetry.NodeAliasesBySelectorCache, telemetry.Count}
	EntriesByEntryID      = []string{telemetry.Entry, telemetry.EntriesByEntryIDCache, telemetry.Count}
	EntriesByParentID     = []string{telemetry.Entry, telemetry.EntriesByParentIDCache, telemetry.Count}
	SkippedEntryEventID   = []string{telemetry.Entry, telemetry.SkippedEntryEventIDs, telemetry.Count}

	defaultRegistrationEntries = []*common.RegistrationEntry{
		&common.RegistrationEntry{
			EntryId:  "47c96201-a4b1-4116-97fe-8aa9c2440aad",
			ParentId: "spiffe://example.org/test_node_1",
			SpiffeId: "spiffe://example.org/test_job_2",
			Selectors: []*common.Selector{
				{Type: "testjob", Value: "2"},
			},
		},
		&common.RegistrationEntry{
			EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
			ParentId: "spiffe://example.org/test_node_2",
			SpiffeId: "spiffe://example.org/test_job_3",
			Selectors: []*common.Selector{
				{Type: "testjob", Value: "3"},
			},
		},
	}
	defaultRegistrationEntryEventsStartingAt60 = []*datastore.RegistrationEntryEvent{
		&datastore.RegistrationEntryEvent{
			EventID: 60,
			EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
		},
		&datastore.RegistrationEntryEvent{
			EventID: 61,
			EntryID: "1d78521b-cc92-47c1-85a5-28ce47f121f2",
		},
	}
	defaultFirstEntryEvent = uint(60)
	defaultLastEntryEvent  = uint(61)

	NoEntryFetches = []string{}
)

func TestLoadEntryCache(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup *entryScenarioSetup

		expectedError               string
		expectedRegistrationEntries []string
		expectedGauges              []expectedGauge
	}{
		{
			name: "initial load returns an error",
			setup: &entryScenarioSetup{
				err: errors.New("any error, doesn't matter"),
			},
			expectedError: "any error, doesn't matter",
		},
		{
			name: "loading nothing with a page size of zero raises an error",
			setup: &entryScenarioSetup{
				pageSize: 0,
			},
			expectedError: "cannot paginate with pagesize = 0",
		},
		{
			name: "initial load loads nothing",
			setup: &entryScenarioSetup{
				pageSize: 1000,
			},
		},
		{
			name: "one registration entry with a page size of zero raises an error",
			setup: &entryScenarioSetup{
				pageSize: 0,
				registrationEntries: []*common.RegistrationEntry{
					&common.RegistrationEntry{
						EntryId:  "6837984a-bc44-462b-9ca6-5cd59be35066",
						ParentId: "spiffe://example.org/test_node_1",
						SpiffeId: "spiffe://example.org/test_job_1",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "1"},
						},
					},
				},
			},
			expectedError: "cannot paginate with pagesize = 0",
		},
		{
			name: "initial load loads one registration entry",
			setup: &entryScenarioSetup{
				pageSize: 1000,
				registrationEntries: []*common.RegistrationEntry{
					&common.RegistrationEntry{
						EntryId:  "6837984a-bc44-462b-9ca6-5cd59be35066",
						ParentId: "spiffe://example.org/test_node_1",
						SpiffeId: "spiffe://example.org/test_job_1",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "1"},
						},
					},
				},
			},
			expectedRegistrationEntries: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
			},
			expectedGauges: []expectedGauge{
				expectedGauge{Key: SkippedEntryEventID, Value: 0},
				expectedGauge{Key: NodeAliasesByEntryID, Value: 0},
				expectedGauge{Key: NodeAliasesBySelector, Value: 0},
				expectedGauge{Key: EntriesByEntryID, Value: 1},
				expectedGauge{Key: EntriesByParentID, Value: 1},
			},
		},
		{
			name: "five registration entries with a page size of zero raises an error",
			setup: &entryScenarioSetup{
				pageSize: 0,
				registrationEntries: []*common.RegistrationEntry{
					&common.RegistrationEntry{
						EntryId:  "6837984a-bc44-462b-9ca6-5cd59be35066",
						ParentId: "spiffe://example.org/test_node_1",
						SpiffeId: "spiffe://example.org/test_job_1",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "1"},
						},
					},
					&common.RegistrationEntry{
						EntryId:  "47c96201-a4b1-4116-97fe-8aa9c2440aad",
						ParentId: "spiffe://example.org/test_node_1",
						SpiffeId: "spiffe://example.org/test_job_2",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "2"},
						},
					},
					&common.RegistrationEntry{
						EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_3",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "3"},
						},
					},
					&common.RegistrationEntry{
						EntryId:  "8cbf7d48-9d43-41ae-ab63-77d66891f948",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_4",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "4"},
						},
					},
					&common.RegistrationEntry{
						EntryId:  "354c16f4-4e61-4c17-8596-7baa7744d504",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_5",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "5"},
						},
					},
				},
			},
			expectedError: "cannot paginate with pagesize = 0",
		},
		{
			name: "initial load loads five registration entries",
			setup: &entryScenarioSetup{
				pageSize: 1000,
				registrationEntries: []*common.RegistrationEntry{
					&common.RegistrationEntry{
						EntryId:  "6837984a-bc44-462b-9ca6-5cd59be35066",
						ParentId: "spiffe://example.org/test_node_1",
						SpiffeId: "spiffe://example.org/test_job_1",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "1"},
						},
					},
					&common.RegistrationEntry{
						EntryId:  "47c96201-a4b1-4116-97fe-8aa9c2440aad",
						ParentId: "spiffe://example.org/test_node_1",
						SpiffeId: "spiffe://example.org/test_job_2",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "2"},
						},
					},
					&common.RegistrationEntry{
						EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_3",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "3"},
						},
					},
					&common.RegistrationEntry{
						EntryId:  "8cbf7d48-9d43-41ae-ab63-77d66891f948",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_4",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "4"},
						},
					},
					&common.RegistrationEntry{
						EntryId:  "354c16f4-4e61-4c17-8596-7baa7744d504",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_5",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "5"},
						},
					},
				},
			},
			expectedRegistrationEntries: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
				"354c16f4-4e61-4c17-8596-7baa7744d504",
			},
			expectedGauges: []expectedGauge{
				expectedGauge{Key: SkippedEntryEventID, Value: 0},
				expectedGauge{Key: NodeAliasesByEntryID, Value: 0},
				expectedGauge{Key: NodeAliasesBySelector, Value: 0},
				expectedGauge{Key: EntriesByEntryID, Value: 5},
				expectedGauge{Key: EntriesByParentID, Value: 5},
			},
		},
		{
			name: "initial load loads five registration entries, in one page exact",
			setup: &entryScenarioSetup{
				pageSize: 5,
				registrationEntries: []*common.RegistrationEntry{
					&common.RegistrationEntry{
						EntryId:  "6837984a-bc44-462b-9ca6-5cd59be35066",
						ParentId: "spiffe://example.org/test_node_1",
						SpiffeId: "spiffe://example.org/test_job_1",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "1"},
						},
					},
					&common.RegistrationEntry{
						EntryId:  "47c96201-a4b1-4116-97fe-8aa9c2440aad",
						ParentId: "spiffe://example.org/test_node_1",
						SpiffeId: "spiffe://example.org/test_job_2",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "2"},
						},
					},
					&common.RegistrationEntry{
						EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_3",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "3"},
						},
					},
					&common.RegistrationEntry{
						EntryId:  "8cbf7d48-9d43-41ae-ab63-77d66891f948",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_4",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "4"},
						},
					},
					&common.RegistrationEntry{
						EntryId:  "354c16f4-4e61-4c17-8596-7baa7744d504",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_5",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "5"},
						},
					},
				},
			},
			expectedRegistrationEntries: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
				"354c16f4-4e61-4c17-8596-7baa7744d504",
			},
			expectedGauges: []expectedGauge{
				expectedGauge{Key: SkippedEntryEventID, Value: 0},
				expectedGauge{Key: NodeAliasesByEntryID, Value: 0},
				expectedGauge{Key: NodeAliasesBySelector, Value: 0},
				expectedGauge{Key: EntriesByEntryID, Value: 5},
				expectedGauge{Key: EntriesByParentID, Value: 5},
			},
		},
		{
			name: "initial load loads five registration entries, in 2 pages",
			setup: &entryScenarioSetup{
				pageSize: 3,
				registrationEntries: []*common.RegistrationEntry{
					&common.RegistrationEntry{
						EntryId:  "6837984a-bc44-462b-9ca6-5cd59be35066",
						ParentId: "spiffe://example.org/test_node_1",
						SpiffeId: "spiffe://example.org/test_job_1",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "1"},
						},
					},
					&common.RegistrationEntry{
						EntryId:  "47c96201-a4b1-4116-97fe-8aa9c2440aad",
						ParentId: "spiffe://example.org/test_node_1",
						SpiffeId: "spiffe://example.org/test_job_2",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "2"},
						},
					},
					&common.RegistrationEntry{
						EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_3",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "3"},
						},
					},
					&common.RegistrationEntry{
						EntryId:  "8cbf7d48-9d43-41ae-ab63-77d66891f948",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_4",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "4"},
						},
					},
					&common.RegistrationEntry{
						EntryId:  "354c16f4-4e61-4c17-8596-7baa7744d504",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_5",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "5"},
						},
					},
				},
			},
			expectedRegistrationEntries: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
				"354c16f4-4e61-4c17-8596-7baa7744d504",
			},
			expectedGauges: []expectedGauge{
				expectedGauge{Key: SkippedEntryEventID, Value: 0},
				expectedGauge{Key: NodeAliasesByEntryID, Value: 0},
				expectedGauge{Key: NodeAliasesBySelector, Value: 0},
				expectedGauge{Key: EntriesByEntryID, Value: 5},
				expectedGauge{Key: EntriesByParentID, Value: 5},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			scenario := NewEntryScenario(t, tt.setup)
			registrationEntries, err := scenario.buildRegistrationEntriesCache()

			if tt.expectedError != "" {
				t.Logf("expecting error: %s\n", tt.expectedError)
				require.ErrorContains(t, err, tt.expectedError)
				return
			}
			require.NoError(t, err)

			cacheStats := registrationEntries.cache.Stats()
			t.Logf("%s: cache stats %+v\n", tt.name, cacheStats)
			require.Equal(t, len(tt.expectedRegistrationEntries), cacheStats.EntriesByEntryID,
				"wrong number of entries by ID")

			// for now, the only way to ensure the desired agent ids are prsent is
			// to remove the desired ids and check the count it zero.
			for _, expectedRegistrationEntry := range tt.expectedRegistrationEntries {
				registrationEntries.cache.RemoveEntry(expectedRegistrationEntry)
			}
			cacheStats = registrationEntries.cache.Stats()
			require.Equal(t, 0, cacheStats.EntriesByEntryID,
				"clearing all expected entry ids didn't clear cache")

			var lastMetrics map[string]int = make(map[string]int)
			for _, metricItem := range scenario.metrics.AllMetrics() {
				if metricItem.Type == fakemetrics.SetGaugeType {
					key := strings.Join(metricItem.Key, " ")
					lastMetrics[key] = int(metricItem.Val)
					t.Logf("metricItem: %+v\n", metricItem)
				}
			}

			for _, expectedGauge := range tt.expectedGauges {
				key := strings.Join(expectedGauge.Key, " ")
				value, exists := lastMetrics[key]
				require.True(t, exists, "No metric value for %q", key)
				require.Equal(t, expectedGauge.Value, value, "unexpected final metric value for %q", key)
			}

			require.Zero(t, scenario.hook.Entries)
		})
	}
}

func TestSearchBeforeFirstEntryEvent(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup *entryScenarioSetup

		waitToPoll        time.Duration
		eventsBeforeFirst []uint
		polledEvents      []*datastore.RegistrationEntryEvent
		errors            []error

		expectedError             error
		expectedEventsBeforeFirst []uint
		expectedFetches           []string
	}{
		{
			name: "first event not loaded",
			setup: &entryScenarioSetup{
				pageSize: 1024,
			},

			expectedEventsBeforeFirst: []uint{},
			expectedFetches:           []string{},
		},
		{
			name: "before first event arrived, after transaction timeout",
			setup: &entryScenarioSetup{
				pageSize:                1024,
				registrationEntries:     defaultRegistrationEntries,
				registrationEntryEvents: defaultRegistrationEntryEventsStartingAt60,
			},

			waitToPoll: time.Duration(2) * defaultSQLTransactionTimeout,
			// even with new before first events, they shouldn't load
			polledEvents: []*datastore.RegistrationEntryEvent{
				&datastore.RegistrationEntryEvent{
					EventID: 58,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
			},

			expectedEventsBeforeFirst: []uint{},
			expectedFetches:           NoEntryFetches,
		},
		{
			name: "no before first events",

			setup: &entryScenarioSetup{
				pageSize:                1024,
				registrationEntries:     defaultRegistrationEntries,
				registrationEntryEvents: defaultRegistrationEntryEventsStartingAt60,
			},
			polledEvents: []*datastore.RegistrationEntryEvent{},

			expectedEventsBeforeFirst: []uint{},
			expectedFetches:           []string{},
		},
		{
			name: "new before first event",

			setup: &entryScenarioSetup{
				pageSize:                1024,
				registrationEntries:     defaultRegistrationEntries,
				registrationEntryEvents: defaultRegistrationEntryEventsStartingAt60,
			},
			polledEvents: []*datastore.RegistrationEntryEvent{
				&datastore.RegistrationEntryEvent{
					EventID: 58,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
			},

			expectedEventsBeforeFirst: []uint{58},
			expectedFetches: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
			},
		},
		{
			name: "new after last event",

			setup: &entryScenarioSetup{
				pageSize:                1024,
				registrationEntries:     defaultRegistrationEntries,
				registrationEntryEvents: defaultRegistrationEntryEventsStartingAt60,
			},
			polledEvents: []*datastore.RegistrationEntryEvent{
				&datastore.RegistrationEntryEvent{
					EventID: 64,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
			},

			expectedEventsBeforeFirst: []uint{},
			expectedFetches:           []string{},
		},
		{
			name: "previously seen before first event",

			setup: &entryScenarioSetup{
				pageSize:                1024,
				registrationEntries:     defaultRegistrationEntries,
				registrationEntryEvents: defaultRegistrationEntryEventsStartingAt60,
			},
			eventsBeforeFirst: []uint{58},
			polledEvents: []*datastore.RegistrationEntryEvent{
				&datastore.RegistrationEntryEvent{
					EventID: 58,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
			},

			expectedEventsBeforeFirst: []uint{58},
			expectedFetches:           []string{},
		},
		{
			name: "previously seen before first event and after last event",

			setup: &entryScenarioSetup{
				pageSize:                1024,
				registrationEntries:     defaultRegistrationEntries,
				registrationEntryEvents: defaultRegistrationEntryEventsStartingAt60,
			},
			eventsBeforeFirst: []uint{58},
			polledEvents: []*datastore.RegistrationEntryEvent{
				&datastore.RegistrationEntryEvent{
					EventID: defaultFirstEntryEvent - 2,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
				&datastore.RegistrationEntryEvent{
					EventID: defaultLastEntryEvent + 2,
					EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
				},
			},

			expectedEventsBeforeFirst: []uint{defaultFirstEntryEvent - 2},
			expectedFetches:           []string{},
		},
		{
			name: "five new before first events",

			setup: &entryScenarioSetup{
				pageSize:                1024,
				registrationEntries:     defaultRegistrationEntries,
				registrationEntryEvents: defaultRegistrationEntryEventsStartingAt60,
			},
			polledEvents: []*datastore.RegistrationEntryEvent{
				&datastore.RegistrationEntryEvent{
					EventID: 48,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 49,
					EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 53,
					EntryID: "1d78521b-cc92-47c1-85a5-28ce47f121f2",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 56,
					EntryID: "8cbf7d48-9d43-41ae-ab63-77d66891f948",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 57,
					EntryID: "354c16f4-4e61-4c17-8596-7baa7744d504",
				},
			},

			expectedEventsBeforeFirst: []uint{48, 49, 53, 56, 57},
			expectedFetches: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
				"354c16f4-4e61-4c17-8596-7baa7744d504",
			},
		},
		{
			name: "five new before first events, one after last event",

			setup: &entryScenarioSetup{
				pageSize:                1024,
				registrationEntries:     defaultRegistrationEntries,
				registrationEntryEvents: defaultRegistrationEntryEventsStartingAt60,
			},
			polledEvents: []*datastore.RegistrationEntryEvent{
				&datastore.RegistrationEntryEvent{
					EventID: 48,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 49,
					EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 53,
					EntryID: "1d78521b-cc92-47c1-85a5-28ce47f121f2",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 56,
					EntryID: "8cbf7d48-9d43-41ae-ab63-77d66891f948",
				},
				&datastore.RegistrationEntryEvent{
					EventID: defaultLastEntryEvent + 1,
					EntryID: "354c16f4-4e61-4c17-8596-7baa7744d504",
				},
			},

			expectedEventsBeforeFirst: []uint{48, 49, 53, 56},
			expectedFetches: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
			},
		},
		{
			name: "five before first events, two previously seen",
			setup: &entryScenarioSetup{
				pageSize:                1024,
				registrationEntries:     defaultRegistrationEntries,
				registrationEntryEvents: defaultRegistrationEntryEventsStartingAt60,
			},

			eventsBeforeFirst: []uint{48, 49},
			polledEvents: []*datastore.RegistrationEntryEvent{
				&datastore.RegistrationEntryEvent{
					EventID: 48,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 49,
					EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 53,
					EntryID: "1d78521b-cc92-47c1-85a5-28ce47f121f2",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 56,
					EntryID: "8cbf7d48-9d43-41ae-ab63-77d66891f948",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 57,
					EntryID: "354c16f4-4e61-4c17-8596-7baa7744d504",
				},
			},

			expectedEventsBeforeFirst: []uint{48, 49, 53, 56, 57},
			expectedFetches: []string{
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
				"354c16f4-4e61-4c17-8596-7baa7744d504",
			},
		},
		{
			name: "five before first events, two previously seen, one after last event",
			setup: &entryScenarioSetup{
				pageSize:                1024,
				registrationEntries:     defaultRegistrationEntries,
				registrationEntryEvents: defaultRegistrationEntryEventsStartingAt60,
			},
			eventsBeforeFirst: []uint{48, 49},
			polledEvents: []*datastore.RegistrationEntryEvent{
				&datastore.RegistrationEntryEvent{
					EventID: 48,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 49,
					EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 53,
					EntryID: "1d78521b-cc92-47c1-85a5-28ce47f121f2",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 56,
					EntryID: "8cbf7d48-9d43-41ae-ab63-77d66891f948",
				},
				&datastore.RegistrationEntryEvent{
					EventID: defaultLastEntryEvent + 1,
					EntryID: "354c16f4-4e61-4c17-8596-7baa7744d504",
				},
			},

			expectedEventsBeforeFirst: []uint{48, 49, 53, 56},
			expectedFetches: []string{
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
			},
		},
		{
			name: "five before first events, five previously seen",
			setup: &entryScenarioSetup{
				pageSize:                1024,
				registrationEntries:     defaultRegistrationEntries,
				registrationEntryEvents: defaultRegistrationEntryEventsStartingAt60,
			},

			eventsBeforeFirst: []uint{48, 49, 53, 56, 57},
			polledEvents: []*datastore.RegistrationEntryEvent{
				&datastore.RegistrationEntryEvent{
					EventID: 48,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 49,
					EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 53,
					EntryID: "1d78521b-cc92-47c1-85a5-28ce47f121f2",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 56,
					EntryID: "8cbf7d48-9d43-41ae-ab63-77d66891f948",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 57,
					EntryID: "354c16f4-4e61-4c17-8596-7baa7744d504",
				},
			},

			expectedEventsBeforeFirst: []uint{48, 49, 53, 56, 57},
			expectedFetches:           []string{},
		},
		{
			name: "five before first events, five previously seen, with after last event",
			setup: &entryScenarioSetup{
				pageSize:                1024,
				registrationEntries:     defaultRegistrationEntries,
				registrationEntryEvents: defaultRegistrationEntryEventsStartingAt60,
			},

			eventsBeforeFirst: []uint{48, 49, 53, 56, 57},
			polledEvents: []*datastore.RegistrationEntryEvent{
				&datastore.RegistrationEntryEvent{
					EventID: 48,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 49,
					EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 53,
					EntryID: "1d78521b-cc92-47c1-85a5-28ce47f121f2",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 56,
					EntryID: "8cbf7d48-9d43-41ae-ab63-77d66891f948",
				},
				&datastore.RegistrationEntryEvent{
					EventID: 57,
					EntryID: "354c16f4-4e61-4c17-8596-7baa7744d504",
				},
				&datastore.RegistrationEntryEvent{
					EventID: defaultLastEntryEvent + 1,
					EntryID: "aeb603b2-e1d1-4832-8809-60a1d14b42e0",
				},
			},

			expectedEventsBeforeFirst: []uint{48, 49, 53, 56, 57},
			expectedFetches:           []string{},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			scenario := NewEntryScenario(t, tt.setup)
			registrationEntries, err := scenario.buildRegistrationEntriesCache()

			require.NoError(t, err)

			if tt.waitToPoll == 0 {
				scenario.clk.Add(time.Duration(1) * defaultCacheReloadInterval)
			} else {
				scenario.clk.Add(tt.waitToPoll)
			}

			for _, event := range tt.eventsBeforeFirst {
				registrationEntries.eventsBeforeFirst[event] = struct{}{}
			}

			for _, event := range tt.polledEvents {
				scenario.ds.CreateRegistrationEntryEventForTesting(scenario.ctx, event)
			}

			registrationEntries.searchBeforeFirstEvent(scenario.ctx)

			require.ElementsMatch(t, tt.expectedEventsBeforeFirst, slices.Collect(maps.Keys(registrationEntries.eventsBeforeFirst)), "expected events before tracking mismatch")
			require.ElementsMatch(t, tt.expectedFetches, slices.Collect[string](maps.Keys(registrationEntries.fetchEntries)), "expected fetches mismatch")

			require.Zero(t, scenario.hook.Entries)
		})
	}
}

/*
func TestRegistrationEntriesCacheMissedEventNotFound(t *testing.T) {
	ctx := context.Background()
	log, hook := test.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)
	cache := authorizedentries.NewCache(clk)
	metrics := fakemetrics.New()

	registrationEntries, err := buildRegistrationEntriesCache(ctx, log, metrics, ds, clk, cache, buildCachePageSize, defaultSQLTransactionTimeout)
	require.NoError(t, err)
	require.NotNil(t, registrationEntries)

	registrationEntries.missedEvents[1] = clk.Now()
	registrationEntries.replayMissedEvents(ctx)
	require.Zero(t, len(hook.Entries))
}

func TestRegistrationEntriesSavesMissedStartupEvents(t *testing.T) {
	ctx := context.Background()
	log, hook := test.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)
	cache := authorizedentries.NewCache(clk)
	metrics := fakemetrics.New()

	err := ds.CreateRegistrationEntryEventForTesting(ctx, &datastore.RegistrationEntryEvent{
		EventID: 3,
		EntryID: "test",
	})
	require.NoError(t, err)

	registrationEntries, err := buildRegistrationEntriesCache(ctx, log, metrics, ds, clk, cache, buildCachePageSize, defaultSQLTransactionTimeout)
	require.NoError(t, err)
	require.NotNil(t, registrationEntries)
	require.Equal(t, uint(3), registrationEntries.firstEventID)

	err = ds.CreateRegistrationEntryEventForTesting(ctx, &datastore.RegistrationEntryEvent{
		EventID: 2,
		EntryID: "test",
	})
	require.NoError(t, err)

	err = registrationEntries.missedStartupEvents(ctx)
	require.NoError(t, err)

	// Make sure no dupliate calls are made
	ds.AppendNextError(nil)
	ds.AppendNextError(errors.New("Duplicate call"))
	err = registrationEntries.missedStartupEvents(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, len(hook.AllEntries()))
}
*/

type entryScenario struct {
	ctx      context.Context
	log      *logrus.Logger
	hook     *test.Hook
	clk      *clock.Mock
	cache    *authorizedentries.Cache
	metrics  *fakemetrics.FakeMetrics
	ds       *fakedatastore.DataStore
	pageSize int32
}

type entryScenarioSetup struct {
	attestedNodes           []*common.AttestedNode
	attestedNodeEvents      []*datastore.AttestedNodeEvent
	registrationEntries     []*common.RegistrationEntry
	registrationEntryEvents []*datastore.RegistrationEntryEvent
	err                     error
	pageSize                int32
}

func NewEntryScenario(t *testing.T, setup *entryScenarioSetup) *entryScenario {
	t.Helper()
	ctx := context.Background()
	log, hook := test.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)
	clk := clock.NewMock(t)
	cache := authorizedentries.NewCache(clk)
	metrics := fakemetrics.New()
	ds := fakedatastore.New(t)

	if setup == nil {
		setup = &entryScenarioSetup{}
	}

	for _, attestedNode := range setup.attestedNodes {
		ds.CreateAttestedNode(ctx, attestedNode)
	}
	// prune autocreated node events, to test the event logic in more scenarios
	// than possible with autocreated node events.
	ds.PruneAttestedNodesEvents(ctx, time.Duration(-5)*time.Hour)
	// and then add back the specified node events
	for _, event := range setup.attestedNodeEvents {
		ds.CreateAttestedNodeEventForTesting(ctx, event)
	}
	// initialize the database
	for _, registrationEntry := range setup.registrationEntries {
		ds.CreateRegistrationEntry(ctx, registrationEntry)
	}
	// prune autocreated entry events, to test the event logic in more
	// scenarios than possible with autocreated entry events.
	ds.PruneRegistrationEntryEvents(ctx, time.Duration(-5)*time.Hour)
	// and then add back the specified node events
	for _, event := range setup.registrationEntryEvents {
		ds.CreateRegistrationEntryEventForTesting(ctx, event)
	}
	// inject db error for buildRegistrationEntriesCache call
	if setup.err != nil {
		ds.AppendNextError(setup.err)
	}

	return &entryScenario{
		ctx:      ctx,
		log:      log,
		hook:     hook,
		clk:      clk,
		cache:    cache,
		metrics:  metrics,
		ds:       ds,
		pageSize: setup.pageSize,
	}
}

func (s *entryScenario) buildRegistrationEntriesCache() (*registrationEntries, error) {
	registrationEntries, err := buildRegistrationEntriesCache(s.ctx, s.log, s.metrics, s.ds, s.clk, s.cache, s.pageSize, defaultCacheReloadInterval, defaultSQLTransactionTimeout)
	if registrationEntries != nil {
		// clear out the fetches
		for node, _ := range registrationEntries.fetchEntries {
			delete(registrationEntries.fetchEntries, node)
		}
	}
	return registrationEntries, err
}
