package endpoints

import (
	"context"
	"errors"
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
	skippedEntryEventID   = []string{telemetry.Entry, telemetry.SkippedEntryEventIDs, telemetry.Count}
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

			lastMetrics := make(map[string]int)
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
		{
			name: "five new entries in two pages",
			setup: &entryScenarioSetup{
				pageSize: 3,
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
			name: "three new entries, two deletes in three pages",
			setup: &entryScenarioSetup{
				pageSize: 2,
				registrationEntries: []*common.RegistrationEntry{
					{
						EntryId:  "8cbf7d48-9d43-41ae-ab63-77d66891f948",
						ParentId: "spiffe://example.org/test_node_2",
						SpiffeId: "spiffe://example.org/test_job_4",
						Selectors: []*common.Selector{
							{Type: "testjob", Value: "4"},
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
					EntryId:  "1d78521b-cc92-47c1-85a5-28ce47f121f2",
					ParentId: "spiffe://example.org/test_node_2",
					SpiffeId: "spiffe://example.org/test_job_3",
					Selectors: []*common.Selector{
						{Type: "testjob", Value: "3"},
					},
				},
			},
			deleteRegistrationEntries: []string{
				"8cbf7d48-9d43-41ae-ab63-77d66891f948",
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
			},
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
			err = scenario.ds.PruneEvents(scenario.ctx, &datastore.PruneEventsRequest{OlderThan: -5 * time.Hour})
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
	attestedNodes       []*common.AttestedNode
	registrationEntries []*common.RegistrationEntry
	err                 error
	pageSize            int32
}

func NewEntryScenario(t *testing.T, setup *entryScenarioSetup) *entryScenario {
	t.Helper()
	ctx := context.Background()
	log, hook := test.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)
	clk := clock.NewMock(t)
	cache := authorizedentries.NewCache(clk, "example.org")
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
	// initialize the database
	for _, registrationEntry := range setup.registrationEntries {
		_, err = ds.CreateRegistrationEntry(ctx, registrationEntry)
		require.NoError(t, err, "error while setting up test")
	}
	// The cache hydration tests populate refresh queues directly, so discard
	// events produced while setting up entities.
	err = ds.PruneEvents(ctx, &datastore.PruneEventsRequest{OlderThan: -5 * time.Hour})
	require.NoError(t, err, "error while setting up test")
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
	registrationEntries, err := buildRegistrationEntriesCache(s.ctx, s.log, s.metrics, s.ds, s.clk, s.cache, s.pageSize, defaultEventTimeout)
	if registrationEntries != nil {
		// clear out the fetches
		for entry := range registrationEntries.fetchEntries {
			delete(registrationEntries.fetchEntries, entry)
		}
	}
	return registrationEntries, err
}
