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
)

var (
	nodeAliasesByEntryID  = []string{telemetry.Entry, telemetry.NodeAliasesByEntryIDCache, telemetry.Count}
	nodeAliasesBySelector = []string{telemetry.Entry, telemetry.NodeAliasesBySelectorCache, telemetry.Count}
	entriesByEntryID      = []string{telemetry.Entry, telemetry.EntriesByEntryIDCache, telemetry.Count}
	entriesByParentID     = []string{telemetry.Entry, telemetry.EntriesByParentIDCache, telemetry.Count}
	skippedEntryEventID   = []string{telemetry.Entry, telemetry.SkippedEntryEventIDs, telemetry.Count}

	defaultRegistrationEntries = []*common.RegistrationEntry{
		{
			EntryId:  "47c96201-a4b1-4116-97fe-8aa9c2440aad",
			ParentId: "spiffe://example.org/test_node_1",
			SpiffeId: "spiffe://example.org/test_job_2",
			Selectors: []*common.Selector{
				{Type: "testjob", Value: "2"},
			},
		},
		{
			EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
			ParentId: "spiffe://example.org/test_node_2",
			SpiffeId: "spiffe://example.org/test_job_3",
			Selectors: []*common.Selector{
				{Type: "testjob", Value: "3"},
			},
		},
	}
	defaultRegistrationEntryEventsStartingAt60 = []*datastore.RegistrationEntryEvent{
		{
			EventID: 60,
			EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
		},
		{
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
					{
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
					{
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
				{Key: skippedEntryEventID, Value: 0},
				{Key: nodeAliasesByEntryID, Value: 0},
				{Key: nodeAliasesBySelector, Value: 0},
				{Key: entriesByEntryID, Value: 1},
				{Key: entriesByParentID, Value: 1},
			},
		},
		{
			name: "five registration entries with a page size of zero raises an error",
			setup: &entryScenarioSetup{
				pageSize: 0,
				registrationEntries: []*common.RegistrationEntry{
					{
						EntryId:  "6837984a-bc44-462b-9ca6-5cd59be35066",
						ParentId: "spiffe://example.org/test_node_1",
						SpiffeId: "spiffe://example.org/test_job_1",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "1"},
						},
					},
					{
						EntryId:  "47c96201-a4b1-4116-97fe-8aa9c2440aad",
						ParentId: "spiffe://example.org/test_node_1",
						SpiffeId: "spiffe://example.org/test_job_2",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "2"},
						},
					},
					{
						EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_3",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "3"},
						},
					},
					{
						EntryId:  "8cbf7d48-9d43-41ae-ab63-77d66891f948",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_4",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "4"},
						},
					},
					{
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
					{
						EntryId:  "6837984a-bc44-462b-9ca6-5cd59be35066",
						ParentId: "spiffe://example.org/test_node_1",
						SpiffeId: "spiffe://example.org/test_job_1",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "1"},
						},
					},
					{
						EntryId:  "47c96201-a4b1-4116-97fe-8aa9c2440aad",
						ParentId: "spiffe://example.org/test_node_1",
						SpiffeId: "spiffe://example.org/test_job_2",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "2"},
						},
					},
					{
						EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_3",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "3"},
						},
					},
					{
						EntryId:  "8cbf7d48-9d43-41ae-ab63-77d66891f948",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_4",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "4"},
						},
					},
					{
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
				{Key: skippedEntryEventID, Value: 0},
				{Key: nodeAliasesByEntryID, Value: 0},
				{Key: nodeAliasesBySelector, Value: 0},
				{Key: entriesByEntryID, Value: 5},
				{Key: entriesByParentID, Value: 5},
			},
		},
		{
			name: "initial load loads five registration entries, in one page exact",
			setup: &entryScenarioSetup{
				pageSize: 5,
				registrationEntries: []*common.RegistrationEntry{
					{
						EntryId:  "6837984a-bc44-462b-9ca6-5cd59be35066",
						ParentId: "spiffe://example.org/test_node_1",
						SpiffeId: "spiffe://example.org/test_job_1",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "1"},
						},
					},
					{
						EntryId:  "47c96201-a4b1-4116-97fe-8aa9c2440aad",
						ParentId: "spiffe://example.org/test_node_1",
						SpiffeId: "spiffe://example.org/test_job_2",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "2"},
						},
					},
					{
						EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_3",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "3"},
						},
					},
					{
						EntryId:  "8cbf7d48-9d43-41ae-ab63-77d66891f948",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_4",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "4"},
						},
					},
					{
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
				{Key: skippedEntryEventID, Value: 0},
				{Key: nodeAliasesByEntryID, Value: 0},
				{Key: nodeAliasesBySelector, Value: 0},
				{Key: entriesByEntryID, Value: 5},
				{Key: entriesByParentID, Value: 5},
			},
		},
		{
			name: "initial load loads five registration entries, in 2 pages",
			setup: &entryScenarioSetup{
				pageSize: 3,
				registrationEntries: []*common.RegistrationEntry{
					{
						EntryId:  "6837984a-bc44-462b-9ca6-5cd59be35066",
						ParentId: "spiffe://example.org/test_node_1",
						SpiffeId: "spiffe://example.org/test_job_1",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "1"},
						},
					},
					{
						EntryId:  "47c96201-a4b1-4116-97fe-8aa9c2440aad",
						ParentId: "spiffe://example.org/test_node_1",
						SpiffeId: "spiffe://example.org/test_job_2",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "2"},
						},
					},
					{
						EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_3",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "3"},
						},
					},
					{
						EntryId:  "8cbf7d48-9d43-41ae-ab63-77d66891f948",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_4",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "4"},
						},
					},
					{
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
				{Key: skippedEntryEventID, Value: 0},
				{Key: nodeAliasesByEntryID, Value: 0},
				{Key: nodeAliasesBySelector, Value: 0},
				{Key: entriesByEntryID, Value: 5},
				{Key: entriesByParentID, Value: 5},
			},
		},
	} {
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
				{
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
				{
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
				{
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
				{
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
				{
					EventID: defaultFirstEntryEvent - 2,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
				{
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
				{
					EventID: 48,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
				{
					EventID: 49,
					EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
				},
				{
					EventID: 53,
					EntryID: "1d78521b-cc92-47c1-85a5-28ce47f121f2",
				},
				{
					EventID: 56,
					EntryID: "8cbf7d48-9d43-41ae-ab63-77d66891f948",
				},
				{
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
				{
					EventID: 48,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
				{
					EventID: 49,
					EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
				},
				{
					EventID: 53,
					EntryID: "1d78521b-cc92-47c1-85a5-28ce47f121f2",
				},
				{
					EventID: 56,
					EntryID: "8cbf7d48-9d43-41ae-ab63-77d66891f948",
				},
				{
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
				{
					EventID: 48,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
				{
					EventID: 49,
					EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
				},
				{
					EventID: 53,
					EntryID: "1d78521b-cc92-47c1-85a5-28ce47f121f2",
				},
				{
					EventID: 56,
					EntryID: "8cbf7d48-9d43-41ae-ab63-77d66891f948",
				},
				{
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
				{
					EventID: 48,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
				{
					EventID: 49,
					EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
				},
				{
					EventID: 53,
					EntryID: "1d78521b-cc92-47c1-85a5-28ce47f121f2",
				},
				{
					EventID: 56,
					EntryID: "8cbf7d48-9d43-41ae-ab63-77d66891f948",
				},
				{
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
				{
					EventID: 48,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
				{
					EventID: 49,
					EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
				},
				{
					EventID: 53,
					EntryID: "1d78521b-cc92-47c1-85a5-28ce47f121f2",
				},
				{
					EventID: 56,
					EntryID: "8cbf7d48-9d43-41ae-ab63-77d66891f948",
				},
				{
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
				{
					EventID: 48,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
				{
					EventID: 49,
					EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
				},
				{
					EventID: 53,
					EntryID: "1d78521b-cc92-47c1-85a5-28ce47f121f2",
				},
				{
					EventID: 56,
					EntryID: "8cbf7d48-9d43-41ae-ab63-77d66891f948",
				},
				{
					EventID: 57,
					EntryID: "354c16f4-4e61-4c17-8596-7baa7744d504",
				},
				{
					EventID: defaultLastEntryEvent + 1,
					EntryID: "aeb603b2-e1d1-4832-8809-60a1d14b42e0",
				},
			},

			expectedEventsBeforeFirst: []uint{48, 49, 53, 56, 57},
			expectedFetches:           []string{},
		},
	} {
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
				err = scenario.ds.CreateRegistrationEntryEventForTesting(scenario.ctx, event)
				require.NoError(t, err, "error while setting up test")
			}

			err = registrationEntries.searchBeforeFirstEvent(scenario.ctx)
			require.NoError(t, err, "error while running the test")

			require.ElementsMatch(t, tt.expectedEventsBeforeFirst, slices.Collect(maps.Keys(registrationEntries.eventsBeforeFirst)), "expected events before tracking mismatch")
			require.ElementsMatch(t, tt.expectedFetches, slices.Collect[string](maps.Keys(registrationEntries.fetchEntries)), "expected fetches mismatch")

			require.Zero(t, scenario.hook.Entries)
		})
	}
}

func TestSelectedPolledEntryEvents(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup *entryScenarioSetup

		polling         []uint
		events          []*datastore.RegistrationEntryEvent
		expectedFetches []string
	}{
		// polling is based on the eventTracker, not on events in the database
		{
			name:   "nothing after to poll, no action taken, no events",
			events: []*datastore.RegistrationEntryEvent{},
			setup: &entryScenarioSetup{
				pageSize: 1024,
			},
		},
		{
			name: "nothing to poll, no action take, one event",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntryEvents: []*datastore.RegistrationEntryEvent{
					{
						EventID: 100,
						EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
					},
				},
			},
		},
		{
			name: "nothing to poll, no action taken, five events",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntryEvents: []*datastore.RegistrationEntryEvent{
					{
						EventID: 101,
						EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
					},
					{
						EventID: 102,
						EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
					},
					{
						EventID: 103,
						EntryID: "1d78521b-cc92-47c1-85a5-28ce47f121f2",
					},
					{
						EventID: 104,
						EntryID: "8cbf7d48-9d43-41ae-ab63-77d66891f948",
					},
					{
						EventID: 105,
						EntryID: "354c16f4-4e61-4c17-8596-7baa7744d504",
					},
				},
			},
		},
		{
			name: "polling one item, not found",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntryEvents: []*datastore.RegistrationEntryEvent{
					{
						EventID: 101,
						EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
					},
					{
						EventID: 102,
						EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
					},
					{
						EventID: 104,
						EntryID: "8cbf7d48-9d43-41ae-ab63-77d66891f948",
					},
					{
						EventID: 105,
						EntryID: "354c16f4-4e61-4c17-8596-7baa7744d504",
					},
				},
			},
			polling: []uint{103},
		},
		{
			name: "polling five items, not found",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntryEvents: []*datastore.RegistrationEntryEvent{
					{
						EventID: 101,
						EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
					},
					{
						EventID: 107,
						EntryID: "c3f4ada0-3f8d-421e-b5d1-83aaee203d94",
					},
				},
			},
			polling: []uint{102, 103, 104, 105, 106},
		},
		{
			name: "polling one item, found",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntryEvents: []*datastore.RegistrationEntryEvent{
					{
						EventID: 101,
						EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
					},
					{
						EventID: 102,
						EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
					},
					{
						EventID: 103,
						EntryID: "1d78521b-cc92-47c1-85a5-28ce47f121f2",
					},
				},
			},
			polling: []uint{102},

			expectedFetches: []string{
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
			},
		},
		{
			name: "polling five items, two found",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntryEvents: []*datastore.RegistrationEntryEvent{
					{
						EventID: 101,
						EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
					},
					{
						EventID: 103,
						EntryID: "1d78521b-cc92-47c1-85a5-28ce47f121f2",
					},
					{
						EventID: 106,
						EntryID: "aeb603b2-e1d1-4832-8809-60a1d14b42e0",
					},
					{
						EventID: 107,
						EntryID: "c3f4ada0-3f8d-421e-b5d1-83aaee203d94",
					},
				},
			},
			polling: []uint{102, 103, 104, 105, 106},

			expectedFetches: []string{
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
				"aeb603b2-e1d1-4832-8809-60a1d14b42e0",
			},
		},
		{
			name: "polling five items, five found",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntryEvents: []*datastore.RegistrationEntryEvent{
					{
						EventID: 101,
						EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
					},
					{
						EventID: 102,
						EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
					},
					{
						EventID: 103,
						EntryID: "1d78521b-cc92-47c1-85a5-28ce47f121f2",
					},
					{
						EventID: 104,
						EntryID: "8cbf7d48-9d43-41ae-ab63-77d66891f948",
					},
					{
						EventID: 105,
						EntryID: "354c16f4-4e61-4c17-8596-7baa7744d504",
					},
					{
						EventID: 106,
						EntryID: "aeb603b2-e1d1-4832-8809-60a1d14b42e0",
					},
					{
						EventID: 107,
						EntryID: "c3f4ada0-3f8d-421e-b5d1-83aaee203d94",
					},
				},
			},
			polling: []uint{102, 103, 104, 105, 106},

			expectedFetches: []string{
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
				"354c16f4-4e61-4c17-8596-7baa7744d504",
				"aeb603b2-e1d1-4832-8809-60a1d14b42e0",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scenario := NewEntryScenario(t, tt.setup)
			registrationEntries, err := scenario.buildRegistrationEntriesCache()
			require.NoError(t, err)

			// initialize the event tracker
			for _, event := range tt.polling {
				registrationEntries.eventTracker.StartTracking(event)
			}
			// poll the events
			registrationEntries.selectPolledEvents(scenario.ctx)

			require.ElementsMatch(t, tt.expectedFetches, slices.Collect(maps.Keys(registrationEntries.fetchEntries)))
			require.Zero(t, scenario.hook.Entries)
		})
	}
}

func TestScanForNewEntryEvents(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup *entryScenarioSetup

		newEvents []*datastore.RegistrationEntryEvent

		expectedTrackedEvents []uint
		expectedFetches       []string
	}{
		{
			name: "no new events, no first event",
			setup: &entryScenarioSetup{
				pageSize: 1024,
			},

			expectedTrackedEvents: []uint{},
			expectedFetches:       []string{},
		},
		{
			name: "no new event, with first event",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntryEvents: []*datastore.RegistrationEntryEvent{
					{
						EventID: 101,
						EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
					},
				},
			},

			expectedTrackedEvents: []uint{},
			expectedFetches:       []string{},
		},
		{
			name: "one new event",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntryEvents: []*datastore.RegistrationEntryEvent{
					{
						EventID: 101,
						EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
					},
				},
			},
			newEvents: []*datastore.RegistrationEntryEvent{
				{
					EventID: 102,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
			},

			expectedTrackedEvents: []uint{},
			expectedFetches: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
			},
		},
		{
			name: "one new event, skipping an event",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntryEvents: []*datastore.RegistrationEntryEvent{
					{
						EventID: 101,
						EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
					},
				},
			},
			newEvents: []*datastore.RegistrationEntryEvent{
				{
					EventID: 103,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
			},

			expectedTrackedEvents: []uint{102},
			expectedFetches: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
			},
		},
		{
			name: "two new events, same registered event",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntryEvents: []*datastore.RegistrationEntryEvent{
					{
						EventID: 101,
						EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
					},
				},
			},
			newEvents: []*datastore.RegistrationEntryEvent{
				{
					EventID: 102,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
				{
					EventID: 103,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
			},

			expectedTrackedEvents: []uint{},
			expectedFetches: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
			},
		},
		{
			name: "two new events, different attested entries",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntryEvents: []*datastore.RegistrationEntryEvent{
					{
						EventID: 101,
						EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
					},
				},
			},
			newEvents: []*datastore.RegistrationEntryEvent{
				{
					EventID: 102,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
				{
					EventID: 103,
					EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
				},
			},

			expectedTrackedEvents: []uint{},
			expectedFetches: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
			},
		},
		{
			name: "two new events, with a skipped event",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntryEvents: []*datastore.RegistrationEntryEvent{
					{
						EventID: 101,
						EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
					},
				},
			},
			newEvents: []*datastore.RegistrationEntryEvent{
				{
					EventID: 102,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
				{
					EventID: 104,
					EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
				},
			},

			expectedTrackedEvents: []uint{103},
			expectedFetches: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
			},
		},
		{
			name: "two new events, with three skipped events",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntryEvents: []*datastore.RegistrationEntryEvent{
					{
						EventID: 101,
						EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
					},
				},
			},
			newEvents: []*datastore.RegistrationEntryEvent{
				{
					EventID: 102,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
				{
					EventID: 106,
					EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
				},
			},

			expectedTrackedEvents: []uint{103, 104, 105},
			expectedFetches: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
			},
		},
		{
			name: "five events, four new events, two skip regions",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntryEvents: []*datastore.RegistrationEntryEvent{
					{
						EventID: 101,
						EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
					},
					{
						EventID: 102,
						EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
					},
					{
						EventID: 103,
						EntryID: "1d78521b-cc92-47c1-85a5-28ce47f121f2",
					},
					{
						EventID: 104,
						EntryID: "8cbf7d48-9d43-41ae-ab63-77d66891f948",
					},
					{
						EventID: 105,
						EntryID: "354c16f4-4e61-4c17-8596-7baa7744d504",
					},
				},
			},
			newEvents: []*datastore.RegistrationEntryEvent{
				{
					EventID: 108,
					EntryID: "6837984a-bc44-462b-9ca6-5cd59be35066",
				},
				{
					EventID: 109,
					EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
				},
				{
					EventID: 110,
					EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad",
				},
				{
					EventID: 112,
					EntryID: "c3f4ada0-3f8d-421e-b5d1-83aaee203d94",
				},
			},

			expectedTrackedEvents: []uint{106, 107, 111},
			expectedFetches: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
				"c3f4ada0-3f8d-421e-b5d1-83aaee203d94",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scenario := NewEntryScenario(t, tt.setup)
			attestedEntries, err := scenario.buildRegistrationEntriesCache()
			require.NoError(t, err)

			for _, newEvent := range tt.newEvents {
				err = scenario.ds.CreateRegistrationEntryEventForTesting(scenario.ctx, newEvent)
				require.NoError(t, err, "error while setting up test")
			}
			err = attestedEntries.scanForNewEvents(scenario.ctx)
			require.NoError(t, err, "error while running the test")

			require.ElementsMatch(t, tt.expectedTrackedEvents, slices.Collect(maps.Keys(attestedEntries.eventTracker.events)))
			require.ElementsMatch(t, tt.expectedFetches, slices.Collect(maps.Keys(attestedEntries.fetchEntries)))
			require.Zero(t, scenario.hook.Entries)
		})
	}
}

func TestUpdateRegistrationEntriesCache(t *testing.T) {
	for _, tt := range []struct {
		name                      string
		setup                     *entryScenarioSetup
		createRegistrationEntries []*common.RegistrationEntry // Entries created after setup
		deleteRegistrationEntries []string                    // Entries deleted after setup
		fetchEntries              []string

		expectedAuthorizedEntries []string
	}{
		{
			name: "empty cache, no fetch entries",
			setup: &entryScenarioSetup{
				pageSize: 1024,
			},
			fetchEntries: []string{},

			expectedAuthorizedEntries: []string{},
		},
		{
			name: "empty cache, fetch one entry, as a new entry",
			setup: &entryScenarioSetup{
				pageSize: 1024,
			},
			createRegistrationEntries: []*common.RegistrationEntry{
				{
					EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
					ParentId: "spiffe://example.org/test_node_2",
					SpiffeId: "spiffe://example.org/test_job_3",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "3"},
					},
				},
			},
			fetchEntries: []string{
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
			},

			expectedAuthorizedEntries: []string{
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
			},
		},
		{
			name: "empty cache, fetch one entry, as a delete",
			setup: &entryScenarioSetup{
				pageSize: 1024,
			},
			fetchEntries: []string{
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
			},
		},
		{
			name: "empty cache, fetch five entries, all new entries",
			setup: &entryScenarioSetup{
				pageSize: 1024,
			},
			createRegistrationEntries: []*common.RegistrationEntry{
				{
					EntryId:  "6837984a-bc44-462b-9ca6-5cd59be35066",
					ParentId: "spiffe://example.org/test_node_1",
					SpiffeId: "spiffe://example.org/test_job_1",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "1"},
					},
				},
				{
					EntryId:  "47c96201-a4b1-4116-97fe-8aa9c2440aad",
					ParentId: "spiffe://example.org/test_node_1",
					SpiffeId: "spiffe://example.org/test_job_2",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "2"},
					},
				},
				{
					EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
					ParentId: "spiffe://example.org/test_node_2",
					SpiffeId: "spiffe://example.org/test_job_3",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "3"},
					},
				},
				{
					EntryId:  "8cbf7d48-9d43-41ae-ab63-77d66891f948",
					ParentId: "spiffe://example.org/test_node_2",
					SpiffeId: "spiffe://example.org/test_job_4",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "4"},
					},
				},
				{
					EntryId:  "354c16f4-4e61-4c17-8596-7baa7744d504",
					ParentId: "spiffe://example.org/test_node_2",
					SpiffeId: "spiffe://example.org/test_job_5",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "5"},
					},
				},
			},
			fetchEntries: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
				"354c16f4-4e61-4c17-8596-7baa7744d504",
			},

			expectedAuthorizedEntries: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
				"354c16f4-4e61-4c17-8596-7baa7744d504",
			},
		},
		{
			name: "empty cache, fetch five entries, three new and two deletes",
			setup: &entryScenarioSetup{
				pageSize: 1024,
			},
			createRegistrationEntries: []*common.RegistrationEntry{
				{
					EntryId:  "6837984a-bc44-462b-9ca6-5cd59be35066",
					ParentId: "spiffe://example.org/test_node_1",
					SpiffeId: "spiffe://example.org/test_job_1",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "1"},
					},
				},
				{
					EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
					ParentId: "spiffe://example.org/test_node_2",
					SpiffeId: "spiffe://example.org/test_job_3",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "3"},
					},
				},
				{
					EntryId:  "8cbf7d48-9d43-41ae-ab63-77d66891f948",
					ParentId: "spiffe://example.org/test_node_2",
					SpiffeId: "spiffe://example.org/test_job_4",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "4"},
					},
				},
			},
			fetchEntries: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
				"354c16f4-4e61-4c17-8596-7baa7744d504",
			},

			expectedAuthorizedEntries: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
			},
		},
		{
			name: "empty cache, fetch five entries, all deletes",
			setup: &entryScenarioSetup{
				pageSize: 1024,
			},
			fetchEntries: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
				"354c16f4-4e61-4c17-8596-7baa7744d504",
			},

			expectedAuthorizedEntries: []string{},
		},
		{
			name: "one entry in cache, no fetch entries",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntries: []*common.RegistrationEntry{
					{
						EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_3",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "3"},
						},
					},
				},
			},

			expectedAuthorizedEntries: []string{
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
			},
		},
		{
			name: "one entry in cache, fetch one entry, as new entry",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntries: []*common.RegistrationEntry{
					{
						EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_3",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "3"},
						},
					},
				},
			},
			createRegistrationEntries: []*common.RegistrationEntry{
				{
					EntryId:  "8cbf7d48-9d43-41ae-ab63-77d66891f948",
					ParentId: "spiffe://example.org/test_node_2",
					SpiffeId: "spiffe://example.org/test_job_4",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "4"},
					},
				},
			},
			fetchEntries: []string{
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
			},

			expectedAuthorizedEntries: []string{
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
			},
		},
		{
			name: "one entry in cache, fetch one entry, as an update",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntries: []*common.RegistrationEntry{
					{
						EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_3",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "3"},
						},
					},
				},
			},
			fetchEntries: []string{
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
			},

			expectedAuthorizedEntries: []string{
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
			},
		},
		{
			name: "one entry in cache, fetch one entry, as a delete",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntries: []*common.RegistrationEntry{
					{
						EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_3",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "3"},
						},
					},
				},
			},
			deleteRegistrationEntries: []string{
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
			},
			fetchEntries: []string{
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
			},

			expectedAuthorizedEntries: []string{},
		},
		{
			name: "one entry in cache, fetch five entries, all new entries",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntries: []*common.RegistrationEntry{
					{
						EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_3",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "3"},
						},
					},
				},
			},
			createRegistrationEntries: []*common.RegistrationEntry{
				{
					EntryId:  "6837984a-bc44-462b-9ca6-5cd59be35066",
					ParentId: "spiffe://example.org/test_node_1",
					SpiffeId: "spiffe://example.org/test_job_1",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "1"},
					},
				},
				{
					EntryId:  "47c96201-a4b1-4116-97fe-8aa9c2440aad",
					ParentId: "spiffe://example.org/test_node_1",
					SpiffeId: "spiffe://example.org/test_job_2",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "2"},
					},
				},
				{
					EntryId:  "8cbf7d48-9d43-41ae-ab63-77d66891f948",
					ParentId: "spiffe://example.org/test_node_2",
					SpiffeId: "spiffe://example.org/test_job_4",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "4"},
					},
				},
				{
					EntryId:  "354c16f4-4e61-4c17-8596-7baa7744d504",
					ParentId: "spiffe://example.org/test_node_2",
					SpiffeId: "spiffe://example.org/test_job_5",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "5"},
					},
				},
				{
					EntryId:  "aeb603b2-e1d1-4832-8809-60a1d14b42e0",
					ParentId: "spiffe://example.org/test_node_3",
					SpiffeId: "spiffe://example.org/test_job_6",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "6"},
					},
				},
			},
			fetchEntries: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
				"354c16f4-4e61-4c17-8596-7baa7744d504",
				"aeb603b2-e1d1-4832-8809-60a1d14b42e0",
			},

			expectedAuthorizedEntries: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
				"354c16f4-4e61-4c17-8596-7baa7744d504",
				"aeb603b2-e1d1-4832-8809-60a1d14b42e0",
			},
		},
		{
			name: "one entry in cache, fetch five entries, four new entries and one update",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntries: []*common.RegistrationEntry{
					{
						EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_3",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "3"},
						},
					},
				},
			},
			createRegistrationEntries: []*common.RegistrationEntry{
				{
					EntryId:  "6837984a-bc44-462b-9ca6-5cd59be35066",
					ParentId: "spiffe://example.org/test_node_1",
					SpiffeId: "spiffe://example.org/test_job_1",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "1"},
					},
				},
				{
					EntryId:  "47c96201-a4b1-4116-97fe-8aa9c2440aad",
					ParentId: "spiffe://example.org/test_node_1",
					SpiffeId: "spiffe://example.org/test_job_2",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "2"},
					},
				},
				{
					EntryId:  "8cbf7d48-9d43-41ae-ab63-77d66891f948",
					ParentId: "spiffe://example.org/test_node_2",
					SpiffeId: "spiffe://example.org/test_job_4",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "4"},
					},
				},
				{
					EntryId:  "354c16f4-4e61-4c17-8596-7baa7744d504",
					ParentId: "spiffe://example.org/test_node_2",
					SpiffeId: "spiffe://example.org/test_job_5",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "5"},
					},
				},
			},
			fetchEntries: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
				"354c16f4-4e61-4c17-8596-7baa7744d504",
			},

			expectedAuthorizedEntries: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
				"354c16f4-4e61-4c17-8596-7baa7744d504",
			},
		},
		{
			name: "one entry in cache, fetch five entries, two new and three deletes",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntries: []*common.RegistrationEntry{
					{
						EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_3",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "3"},
						},
					},
				},
			},
			createRegistrationEntries: []*common.RegistrationEntry{
				{
					EntryId:  "6837984a-bc44-462b-9ca6-5cd59be35066",
					ParentId: "spiffe://example.org/test_node_1",
					SpiffeId: "spiffe://example.org/test_job_1",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "1"},
					},
				},
				{
					EntryId:  "47c96201-a4b1-4116-97fe-8aa9c2440aad",
					ParentId: "spiffe://example.org/test_node_1",
					SpiffeId: "spiffe://example.org/test_job_2",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "2"},
					},
				},
			},
			deleteRegistrationEntries: []string{
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
			},
			fetchEntries: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
				"354c16f4-4e61-4c17-8596-7baa7744d504",
			},

			expectedAuthorizedEntries: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
			},
		},
		{
			name: "one entry in cache, fetch five entries, all deletes",
			setup: &entryScenarioSetup{
				pageSize: 1024,
				registrationEntries: []*common.RegistrationEntry{
					{
						EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_3",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "3"},
						},
					},
				},
			},
			deleteRegistrationEntries: []string{
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
			},
			fetchEntries: []string{
				"6837984a-bc44-462b-9ca6-5cd59be35066",
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
				"354c16f4-4e61-4c17-8596-7baa7744d504",
			},

			expectedAuthorizedEntries: []string{},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scenario := NewEntryScenario(t, tt.setup)
			registeredEntries, err := scenario.buildRegistrationEntriesCache()
			require.NoError(t, err)
			for _, registrationEntry := range tt.createRegistrationEntries {
				_, err = scenario.ds.CreateRegistrationEntry(scenario.ctx, registrationEntry)
				require.NoError(t, err, "error while setting up test")
			}
			for _, registrationEntry := range tt.deleteRegistrationEntries {
				_, err = scenario.ds.DeleteRegistrationEntry(scenario.ctx, registrationEntry)
				require.NoError(t, err, "error while setting up test")
			}
			for _, fetchEntry := range tt.fetchEntries {
				registeredEntries.fetchEntries[fetchEntry] = struct{}{}
			}
			// clear out the events, to prove updates are not event based
			err = scenario.ds.PruneRegistrationEntryEvents(scenario.ctx, time.Duration(-5)*time.Hour)
			require.NoError(t, err, "error while running the test")

			err = registeredEntries.updateCachedEntries(scenario.ctx)
			require.NoError(t, err)

			cacheStats := registeredEntries.cache.Stats()
			require.Equal(t, len(tt.expectedAuthorizedEntries), cacheStats.EntriesByEntryID, "wrong number of registered entries by ID")

			// for now, the only way to ensure the desired agent ids are present is
			// to remove the desired ids and check that the count is zero.
			for _, expectedAuthorizedId := range tt.expectedAuthorizedEntries {
				registeredEntries.cache.RemoveEntry(expectedAuthorizedId)
			}
			cacheStats = registeredEntries.cache.Stats()
			require.Equal(t, 0, cacheStats.EntriesByEntryID, "clearing all expected registered entries didn't clear cache")
		})
	}
}

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

	var err error
	for _, attestedNode := range setup.attestedNodes {
		_, err = ds.CreateAttestedNode(ctx, attestedNode)
		require.NoError(t, err, "error while setting up test")
	}
	// prune autocreated node events, to test the event logic in more scenarios
	// than possible with autocreated node events.
	err = ds.PruneAttestedNodeEvents(ctx, time.Duration(-5)*time.Hour)
	require.NoError(t, err, "error while setting up test")
	// and then add back the specified node events
	for _, event := range setup.attestedNodeEvents {
		err = ds.CreateAttestedNodeEventForTesting(ctx, event)
		require.NoError(t, err, "error while setting up test")
	}
	// initialize the database
	for _, registrationEntry := range setup.registrationEntries {
		_, err = ds.CreateRegistrationEntry(ctx, registrationEntry)
		require.NoError(t, err, "error while setting up test")
	}
	// prune autocreated entry events, to test the event logic in more
	// scenarios than possible with autocreated entry events.
	err = ds.PruneRegistrationEntryEvents(ctx, time.Duration(-5)*time.Hour)
	require.NoError(t, err, "error while setting up test")
	// and then add back the specified node events
	for _, event := range setup.registrationEntryEvents {
		err = ds.CreateRegistrationEntryEventForTesting(ctx, event)
		require.NoError(t, err, "error while setting up test")
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
		for entry := range registrationEntries.fetchEntries {
			delete(registrationEntries.fetchEntries, entry)
		}
	}
	return registrationEntries, err
}
