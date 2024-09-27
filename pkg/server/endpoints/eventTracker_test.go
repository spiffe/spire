package endpoints_test

import (
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/server/endpoints"
	"github.com/stretchr/testify/require"
)

func TestPollPeriods(t *testing.T) {
	for _, tt := range []struct {
		name         string
		pollInterval time.Duration
		pollDuration time.Duration

		expectedPollPeriods uint
	}{
		{
			name:         "polling always polls at least once, even for zero duration",
			pollInterval: time.Duration(1) * time.Minute,
			pollDuration: time.Duration(0) * time.Minute,

			expectedPollPeriods: 1,
		},
		{
			name:         "polling always polls at least once, even for negative durations",
			pollInterval: time.Duration(1) * time.Minute,
			pollDuration: time.Duration(-10) * time.Minute,

			expectedPollPeriods: 1,
		},
		{
			name:         "minimum poll interval of one second",
			pollInterval: time.Duration(0) * time.Second,
			pollDuration: time.Duration(10) * time.Second,

			expectedPollPeriods: 10,
		},
		{
			name:         "minimum poll interval of one second, even for negative intervals",
			pollInterval: time.Duration(-100) * time.Second,
			pollDuration: time.Duration(10) * time.Second,

			expectedPollPeriods: 10,
		},
		{
			name:         "polling every minute in two mintues",
			pollInterval: time.Minute * time.Duration(1),
			pollDuration: time.Minute * time.Duration(2),

			expectedPollPeriods: 2,
		},
		{
			name:         "polling every minute of an hours",
			pollInterval: time.Minute * time.Duration(1),
			pollDuration: time.Hour * time.Duration(1),

			expectedPollPeriods: 60,
		},
		{
			name:         "polling rounds up",
			pollInterval: time.Minute * time.Duration(3),
			pollDuration: time.Minute * time.Duration(10),

			expectedPollPeriods: 4,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			pollPeriods := endpoints.PollPeriods(tt.pollInterval, tt.pollDuration)

			require.Equal(t, tt.expectedPollPeriods, pollPeriods, "interval %s, polled over %s yeilds %d poll periods, not %d poll periods", tt.pollInterval.String(), tt.pollDuration.String(), pollPeriods, tt.expectedPollPeriods)
		})
	}
}

func TestNewEventTracker(t *testing.T) {
	for _, tt := range []struct {
		name        string
		pollPeriods uint
		boundaries  []uint

		expectedInitialPolls uint
		expectedPollPeriods  uint
		expectedPolls        uint
		expectedBoundaries   []uint
	}{
		{
			name:        "polling always polls at least once",
			pollPeriods: 0,
			boundaries:  []uint{},

			expectedInitialPolls: 1,
			expectedPollPeriods:  1,
			expectedPolls:        1,
			expectedBoundaries:   []uint{},
		},
		{
			name:        "polling once, pre-boundary",
			pollPeriods: 1,
			boundaries:  []uint{},

			expectedInitialPolls: 1,
			expectedPollPeriods:  1,
			expectedPolls:        1,
			expectedBoundaries:   []uint{},
		},
		{
			name:        "polling once, in one bucket boundary",
			pollPeriods: 1,
			boundaries:  []uint{0},

			expectedInitialPolls: 0,
			expectedPollPeriods:  1,
			expectedPolls:        1,
			expectedBoundaries:   []uint{0},
		},
		{
			name:        "polling twice, both initial",
			pollPeriods: 2,
			boundaries:  []uint{},

			expectedInitialPolls: 2,
			expectedPollPeriods:  2,
			expectedPolls:        2,
			expectedBoundaries:   []uint{},
		},
		{
			name:        "polling twice, once initial, once in one bucket boundary",
			pollPeriods: 2,
			boundaries:  []uint{1},

			expectedInitialPolls: 1,
			expectedPollPeriods:  2,
			expectedPolls:        2,
			expectedBoundaries:   []uint{1},
		},
		{
			name:        "polling once, in two bucket boundary",
			pollPeriods: 2,
			boundaries:  []uint{0},

			expectedInitialPolls: 0,
			expectedPollPeriods:  2,
			expectedPolls:        1,
			expectedBoundaries:   []uint{0},
		},
		{
			name:        "polling once, in three bucket boundary",
			pollPeriods: 3,
			boundaries:  []uint{0},

			expectedInitialPolls: 0,
			expectedPollPeriods:  3,
			expectedPolls:        1,
			expectedBoundaries:   []uint{0},
		},
		{
			name:        "polling six times in exponential backoff",
			pollPeriods: 120,
			boundaries:  []uint{0, 2, 6, 14, 30, 62},

			expectedInitialPolls: 0,
			expectedPollPeriods:  120,
			expectedPolls:        6,
			expectedBoundaries:   []uint{0, 2, 6, 14, 30, 62},
		},
		{
			name:        "distributed linear polling for a while, then exponential",
			pollPeriods: 600,
			boundaries:  []uint{0, 10, 20, 30, 40, 50, 60, 120, 240, 480},

			expectedInitialPolls: 0,
			expectedPollPeriods:  600,
			expectedPolls:        10,
			expectedBoundaries:   []uint{0, 10, 20, 30, 40, 50, 60, 120, 240, 480},
		},
		{
			name:        "clip boundaries outside of poll periods",
			pollPeriods: 600,
			boundaries:  []uint{0, 10, 20, 30, 40, 50, 60, 120, 240, 480, 9600},

			expectedInitialPolls: 0,
			expectedPollPeriods:  600,
			expectedPolls:        10,
			expectedBoundaries:   []uint{0, 10, 20, 30, 40, 50, 60, 120, 240, 480},
		},
		{
			name:        "order of boundaries doesn't matter",
			pollPeriods: 600,
			boundaries:  []uint{240, 480, 9600, 0, 10, 50, 60, 120, 20, 30, 40},

			expectedInitialPolls: 0,
			expectedPollPeriods:  600,
			expectedPolls:        10,
			expectedBoundaries:   []uint{0, 10, 20, 30, 40, 50, 60, 120, 240, 480},
		},
		{
			name:        "duplicate boundaries are collapsed",
			pollPeriods: 600,
			boundaries:  []uint{0, 10, 10, 10, 20, 30, 40, 50, 60, 60, 120, 240, 480, 240, 9600},

			expectedInitialPolls: 0,
			expectedPollPeriods:  600,
			expectedPolls:        10,
			expectedBoundaries:   []uint{0, 10, 20, 30, 40, 50, 60, 120, 240, 480},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			eventTracker := endpoints.NewEventTracker(tt.pollPeriods, tt.boundaries)

			require.Equal(t, tt.expectedPollPeriods, eventTracker.PollPeriods(), "expcting %d poll periods; but, %d poll periods reported", eventTracker.PollPeriods(), tt.expectedPollPeriods)

			require.Equal(t, tt.expectedBoundaries, eventTracker.PollBoundaries(), "expected %v boundaries, not %v boundaries", eventTracker.PollBoundaries(), tt.expectedBoundaries)
			require.Equal(t, tt.expectedInitialPolls, eventTracker.InitialPolls(), "inital polls of %d when requesting %d", eventTracker.InitialPolls(), tt.expectedInitialPolls)
			require.Equal(t, tt.expectedPolls, eventTracker.Polls(), "polling each element %d times, when expecting %d times", tt.expectedPolls, eventTracker.Polls())
		})
	}
}

func TestEvenTrackerPolling(t *testing.T) {
	for _, tt := range []struct {
		name        string
		pollPeriods uint
		boundaries  []uint

		trackEvents    [][]uint
		expectedPolls  uint
		expectedEvents [][]uint
	}{
		{
			name:        "every event is polled at least once, even when zero polling periods",
			pollPeriods: 0,
			boundaries:  []uint{},
			trackEvents: [][]uint{
				{5, 11, 12, 15},
				{6, 7, 8, 9, 10},
			},

			expectedPolls: 1,
			expectedEvents: [][]uint{
				{5, 11, 12, 15},
				{6, 7, 8, 9, 10},
				{},
			},
		},
		{
			name:        "polling each event once, initial period",
			pollPeriods: 1,
			boundaries:  []uint{},
			trackEvents: [][]uint{
				{5, 11, 12, 15},
				{6, 7, 8, 9, 10},
			},

			expectedPolls: 1,
			expectedEvents: [][]uint{
				{5, 11, 12, 15},
				{6, 7, 8, 9, 10},
				{},
			},
		},
		{
			name:        "polling each event twice, initial period",
			pollPeriods: 2,
			boundaries:  []uint{},
			trackEvents: [][]uint{
				{5, 11, 12, 15},
				{6, 7, 8, 9, 10},
			},

			expectedPolls: 2,
			expectedEvents: [][]uint{
				{5, 11, 12, 15},
				{5, 6, 7, 8, 9, 10, 11, 12, 15},
				{6, 7, 8, 9, 10},
				{},
			},
		},
		{
			name:        "polling each event thrice, initial period",
			pollPeriods: 3,
			boundaries:  []uint{},
			trackEvents: [][]uint{
				{5, 11, 12, 15},
				{6, 7, 8, 9, 10},
				{1, 2, 3, 4, 13},
			},

			expectedPolls: 3,
			expectedEvents: [][]uint{
				{5, 11, 12, 15},
				{5, 6, 7, 8, 9, 10, 11, 12, 15},
				{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15},
				{1, 2, 3, 4, 6, 7, 8, 9, 10, 13},
				{1, 2, 3, 4, 13},
				{},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			eventTracker := endpoints.NewEventTracker(tt.pollPeriods, tt.boundaries)
			require.Equal(t, tt.expectedPolls, eventTracker.Polls(),
				"expecting %d polls per event, but event tracker reports %d polls per event",
				tt.expectedPolls, eventTracker.Polls())

			pollCount := make(map[uint]uint)

			// run the simulation over what we expect
			for index, expectedEvents := range tt.expectedEvents {
				// if there are new tracking requests, add them
				if index < len(tt.trackEvents) {
					for _, event := range tt.trackEvents[index] {
						eventTracker.StartTracking(event)
					}
				}
				// get the events we should poll
				events := eventTracker.SelectEvents()
				// update count for each event
				for _, event := range events {
					pollCount[event]++
				}
				// see if the results match the expecations
				require.ElementsMatch(t, expectedEvents, events,
					"At time step %d, expected set of Events %v, received %v",
					index, expectedEvents, events)
			}
			for event, polls := range pollCount {
				require.Equal(t, tt.expectedPolls, polls,
					"expecting %d polls for event %d, but received %d polls",
					tt.expectedPolls, polls, event)
			}
		})
	}
}

func TestEvenDispersion(t *testing.T) {
	for _, tt := range []struct {
		name        string
		pollPeriods uint

		startEvent     uint
		eventIncrement uint
		eventCount     uint

		expectedSlotCount     uint
		permissibleCountError uint
	}{
		{
			// sequence of Events: 0, 2, 4, 6, 8, 10, 12, ...
			name:           "increment by 2 (offset 0) events distribute fairly across 2 slots",
			pollPeriods:    2,
			startEvent:     0,
			eventIncrement: 2,
			eventCount:     1000,

			// should disperse into two slots, with an approxmiate count of [ 500, 500 ]
			expectedSlotCount:     500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			// sequence of Events: 1, 3, 5, 7, 9, 11, 13, ...
			name:           "increment by 2 (offset 1) events distribute fairly across 2 slots",
			pollPeriods:    2,
			startEvent:     1,
			eventIncrement: 2,
			eventCount:     1000,

			// should disperse into two slots, with an approxmiate count of [ 500, 500 ]
			expectedSlotCount:     500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			// sequence of Events: 0, 3, 6, 9, 12, 15, ...
			name:           "increment by 3 (offset 0) events distribute fairly across 2 slots",
			pollPeriods:    2,
			startEvent:     0,
			eventIncrement: 3,
			eventCount:     1000,

			// should disperse into two slots, with an approxmiate count of [ 500, 500 ]
			expectedSlotCount:     500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			// sequence of Events: 1, 4, 7, 10, 13, 16, ...
			name:           "increment by 3 (offset 1) events distribute fairly across 2 slots",
			pollPeriods:    2,
			startEvent:     1,
			eventIncrement: 3,
			eventCount:     1000,

			// should disperse into two slots, with an approxmiate count of [ 500, 500 ]
			expectedSlotCount:     500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			// sequence of Events: 2, 5, 8, 11, 14, 17, ...
			name:           "increment by 3 (offset 2) events distribute fairly across 2 slots",
			pollPeriods:    2,
			startEvent:     2,
			eventIncrement: 3,
			eventCount:     1000,

			// should disperse into two slots, with an approxmiate count of [ 500, 500 ]
			expectedSlotCount:     500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			// sequence of Events: 0, 4, 8, 12, 16, 20, ...
			name:           "increment by 4 (offset 0) events distribute fairly across 2 slots",
			pollPeriods:    2,
			startEvent:     0,
			eventIncrement: 4,
			eventCount:     1000,

			// should disperse into two slots, with an approxmiate count of [ 500, 500 ]
			expectedSlotCount:     500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			// sequence of Events: 1, 5, 9, 13, 17, 21, ...
			name:           "increment by 4 (offset 1) events distribute fairly across 2 slots",
			pollPeriods:    2,
			startEvent:     1,
			eventIncrement: 4,
			eventCount:     1000,

			// should disperse into two slots, with an approxmiate count of [ 500, 500 ]
			expectedSlotCount:     500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			// sequence of Events: 2, 6, 10, 14, 18, 22, ...
			name:           "increment by 4 (offset 2) events distribute fairly across 2 slots",
			pollPeriods:    2,
			startEvent:     2,
			eventIncrement: 4,
			eventCount:     1000,

			// should disperse into two slots, with an approxmiate count of [ 500, 500 ]
			expectedSlotCount:     500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			// sequence of Events: 3, 7, 11, 15, 19, 23, ...
			name:           "increment by 4 (offset 3) events distribute fairly across 2 slots",
			pollPeriods:    2,
			startEvent:     3,
			eventIncrement: 4,
			eventCount:     1000,

			// should disperse into two slots, with an approxmiate count of [ 500, 500 ]
			expectedSlotCount:     500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			// sequence of Events: 0, 5, 10, 15, 20, 25, ...
			name:           "increment by 5 (offset 0) events distribute fairly across 2 slots",
			pollPeriods:    2,
			startEvent:     0,
			eventIncrement: 5,
			eventCount:     1000,

			// should disperse into two slots, with an approxmiate count of [ 500, 500 ]
			expectedSlotCount:     500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			// sequence of Events: 1, 6, 11, 16, 21, 26, ...
			name:           "increment by 5 (offset 1) events distribute fairly across 2 slots",
			pollPeriods:    2,
			startEvent:     1,
			eventIncrement: 5,
			eventCount:     1000,

			// should disperse into two slots, with an approxmiate count of [ 500, 500 ]
			expectedSlotCount:     500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			// sequence of Events: 2, 7, 12, 17, 22, 27, ...
			name:           "increment by 5 (offset 2) events distribute fairly across 2 slots",
			pollPeriods:    2,
			startEvent:     2,
			eventIncrement: 5,
			eventCount:     1000,

			// should disperse into two slots, with an approxmiate count of [ 500, 500 ]
			expectedSlotCount:     500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			// sequence of Events: 3, 8, 13, 18, 23, 28, ...
			name:           "increment by 5 (offset 3) events distribute fairly across 2 slots",
			pollPeriods:    2,
			startEvent:     3,
			eventIncrement: 5,
			eventCount:     1000,

			// should disperse into two slots, with an approxmiate count of [ 500, 500 ]
			expectedSlotCount:     500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			// sequence of Events: 4, 9, 14, 19, 24, 29, ...
			name:           "increment by 5 (offset 4) events distribute fairly across 2 slots",
			pollPeriods:    2,
			startEvent:     4,
			eventIncrement: 5,
			eventCount:     1000,

			// should disperse into two slots, with an approxmiate count of [ 500, 500 ]
			expectedSlotCount:     500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			// sequence of Events: 0, 2, 4, 6, 8, 10, 12, ...
			name:           "increment by 2 (offset 0) events distribute fairly across 3 slots",
			pollPeriods:    3,
			startEvent:     0,
			eventIncrement: 2,
			eventCount:     1000,

			// should disperse into three slots, with an approxmiate count of [ 333, 333, 333 ]
			expectedSlotCount:     333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 2 (offset 1) events distribute fairly across 3 slots",
			pollPeriods:    3,
			startEvent:     1,
			eventIncrement: 2,
			eventCount:     1000,

			expectedSlotCount:     333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 3 (offset 0) events distribute fairly across 3 slots",
			pollPeriods:    3,
			startEvent:     0,
			eventIncrement: 3,
			eventCount:     1000,

			expectedSlotCount:     333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 3 (offset 1) events distribute fairly across 3 slots",
			pollPeriods:    3,
			startEvent:     1,
			eventIncrement: 3,
			eventCount:     1000,

			expectedSlotCount:     333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 3 (offset 2) events distribute fairly across 3 slots",
			pollPeriods:    3,
			startEvent:     2,
			eventIncrement: 3,
			eventCount:     1000,

			expectedSlotCount:     333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 4 (offset 0) events distribute fairly across 3 slots",
			pollPeriods:    3,
			startEvent:     0,
			eventIncrement: 4,
			eventCount:     1000,

			expectedSlotCount:     333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 4 (offset 1) events distribute fairly across 3 slots",
			pollPeriods:    3,
			startEvent:     1,
			eventIncrement: 4,
			eventCount:     1000,

			expectedSlotCount:     333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 4 (offset 2) events distribute fairly across 3 slots",
			pollPeriods:    3,
			startEvent:     2,
			eventIncrement: 4,
			eventCount:     1000,

			expectedSlotCount:     333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 4 (offset 3) events distribute fairly across 3 slots",
			pollPeriods:    3,
			startEvent:     3,
			eventIncrement: 4,
			eventCount:     1000,

			expectedSlotCount:     333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 5 (offset 0) events distribute fairly across 3 slots",
			pollPeriods:    3,
			startEvent:     0,
			eventIncrement: 5,
			eventCount:     1000,

			expectedSlotCount:     333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 5 (offset 1) events distribute fairly across 3 slots",
			pollPeriods:    3,
			startEvent:     1,
			eventIncrement: 5,
			eventCount:     1000,

			expectedSlotCount:     333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 5 (offset 2) events distribute fairly across 3 slots",
			pollPeriods:    3,
			startEvent:     2,
			eventIncrement: 5,
			eventCount:     1000,

			expectedSlotCount:     333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 5 (offset 3) events distribute fairly across 3 slots",
			pollPeriods:    3,
			startEvent:     3,
			eventIncrement: 5,
			eventCount:     1000,

			expectedSlotCount:     333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 5 (offset 4) events distribute fairly across 3 slots",
			pollPeriods:    3,
			startEvent:     4,
			eventIncrement: 5,
			eventCount:     1000,

			expectedSlotCount:     333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			// sequence of Events: 0, 2, 4, 6, 8, 10, 12, ...
			name:           "increment by 2 (offset 0) events distribute fairly across 4 slots",
			pollPeriods:    4,
			startEvent:     0,
			eventIncrement: 2,
			eventCount:     1000,

			// should disperse into four slots, with an approxmiate count of [ 250, 250, 250, 250 ]
			expectedSlotCount:     250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 2 (offset 1) events distribute fairly across 4 slots",
			pollPeriods:    4,
			startEvent:     1,
			eventIncrement: 2,
			eventCount:     1000,

			expectedSlotCount:     250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 3 (offset 0) events distribute fairly across 4 slots",
			pollPeriods:    4,
			startEvent:     0,
			eventIncrement: 3,
			eventCount:     1000,

			expectedSlotCount:     250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 3 (offset 1) events distribute fairly across 4 slots",
			pollPeriods:    4,
			startEvent:     1,
			eventIncrement: 3,
			eventCount:     1000,

			expectedSlotCount:     250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 3 (offset 2) events distribute fairly across 4 slots",
			pollPeriods:    4,
			startEvent:     2,
			eventIncrement: 3,
			eventCount:     1000,

			expectedSlotCount:     250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 4 (offset 0) events distribute fairly across 4 slots",
			pollPeriods:    4,
			startEvent:     0,
			eventIncrement: 4,
			eventCount:     1000,

			expectedSlotCount:     250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 4 (offset 1) events distribute fairly across 4 slots",
			pollPeriods:    4,
			startEvent:     1,
			eventIncrement: 4,
			eventCount:     1000,

			expectedSlotCount:     250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 4 (offset 2) events distribute fairly across 4 slots",
			pollPeriods:    4,
			startEvent:     2,
			eventIncrement: 4,
			eventCount:     1000,

			expectedSlotCount:     250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 4 (offset 3) events distribute fairly across 4 slots",
			pollPeriods:    4,
			startEvent:     3,
			eventIncrement: 4,
			eventCount:     1000,

			expectedSlotCount:     250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 5 (offset 0) events distribute fairly across 4 slots",
			pollPeriods:    4,
			startEvent:     0,
			eventIncrement: 5,
			eventCount:     1000,

			expectedSlotCount:     250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 5 (offset 1) events distribute fairly across 4 slots",
			pollPeriods:    4,
			startEvent:     1,
			eventIncrement: 5,
			eventCount:     1000,

			expectedSlotCount:     250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 5 (offset 2) events distribute fairly across 4 slots",
			pollPeriods:    4,
			startEvent:     2,
			eventIncrement: 5,
			eventCount:     1000,

			expectedSlotCount:     250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 5 (offset 3) events distribute fairly across 4 slots",
			pollPeriods:    4,
			startEvent:     3,
			eventIncrement: 5,
			eventCount:     1000,

			expectedSlotCount:     250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 5 (offset 4) events distribute fairly across 4 slots",
			pollPeriods:    4,
			startEvent:     4,
			eventIncrement: 5,
			eventCount:     1000,

			expectedSlotCount:     250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			// sequence of Events: 0, 2, 4, 6, 8, 10, 12, ...
			name:           "increment by 2 (offset 0) events distribute fairly across 5 slots",
			pollPeriods:    5,
			startEvent:     0,
			eventIncrement: 2,
			eventCount:     1000,

			// should disperse into five slots, with an approxmiate count of [ 200, 200, 200, 200, 200 ]
			expectedSlotCount:     200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 2 (offset 1) events distribute fairly across 5 slots",
			pollPeriods:    5,
			startEvent:     1,
			eventIncrement: 2,
			eventCount:     1000,

			expectedSlotCount:     200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 3 (offset 0) events distribute fairly across 5 slots",
			pollPeriods:    5,
			startEvent:     0,
			eventIncrement: 3,
			eventCount:     1000,

			expectedSlotCount:     200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 3 (offset 1) events distribute fairly across 5 slots",
			pollPeriods:    5,
			startEvent:     1,
			eventIncrement: 3,
			eventCount:     1000,

			expectedSlotCount:     200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 3 (offset 2) events distribute fairly across 5 slots",
			pollPeriods:    5,
			startEvent:     2,
			eventIncrement: 3,
			eventCount:     1000,

			expectedSlotCount:     200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 4 (offset 0) events distribute fairly across 5 slots",
			pollPeriods:    5,
			startEvent:     0,
			eventIncrement: 4,
			eventCount:     1000,

			expectedSlotCount:     200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 4 (offset 1) events distribute fairly across 5 slots",
			pollPeriods:    5,
			startEvent:     1,
			eventIncrement: 4,
			eventCount:     1000,

			expectedSlotCount:     200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 4 (offset 2) events distribute fairly across 5 slots",
			pollPeriods:    5,
			startEvent:     2,
			eventIncrement: 4,
			eventCount:     1000,

			expectedSlotCount:     200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 4 (offset 3) events distribute fairly across 5 slots",
			pollPeriods:    5,
			startEvent:     3,
			eventIncrement: 4,
			eventCount:     1000,

			expectedSlotCount:     200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 5 (offset 0) events distribute fairly across 5 slots",
			pollPeriods:    5,
			startEvent:     0,
			eventIncrement: 5,
			eventCount:     1000,

			expectedSlotCount:     200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 5 (offset 1) events distribute fairly across 5 slots",
			pollPeriods:    5,
			startEvent:     1,
			eventIncrement: 5,
			eventCount:     1000,

			expectedSlotCount:     200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 5 (offset 2) events distribute fairly across 5 slots",
			pollPeriods:    5,
			startEvent:     2,
			eventIncrement: 5,
			eventCount:     1000,

			expectedSlotCount:     200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 5 (offset 3) events distribute fairly across 5 slots",
			pollPeriods:    5,
			startEvent:     3,
			eventIncrement: 5,
			eventCount:     1000,

			expectedSlotCount:     200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name:           "increment by 5 (offset 4) events distribute fairly across 5 slots",
			pollPeriods:    5,
			startEvent:     4,
			eventIncrement: 5,
			eventCount:     1000,

			expectedSlotCount:     200,
			permissibleCountError: 50, // 5% of 1000
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			eventTracker := endpoints.NewEventTracker(tt.pollPeriods, []uint{0})
			slotCount := make(map[uint]uint)
			for item := range tt.eventCount {
				event := tt.startEvent + tt.eventIncrement*item
				eventTracker.StartTracking(event)
			}
			for pollPeriod := range tt.pollPeriods {
				events := eventTracker.SelectEvents()
				slotCount[pollPeriod] = uint(len(events))
				t.Logf("pollPeriod %d, count = %d", pollPeriod, slotCount[pollPeriod])
			}
			for slot, count := range slotCount {
				require.LessOrEqual(t, tt.expectedSlotCount-tt.permissibleCountError, count,
					"for slot %d, expecting at least %d polls, but received %d polls",
					slot, tt.expectedSlotCount-tt.permissibleCountError, count)
				require.GreaterOrEqual(t, tt.expectedSlotCount+tt.permissibleCountError, count,
					"for slot %d, expecting no more than %d polls, but received %d polls",
					slot, tt.expectedSlotCount+tt.permissibleCountError, count)
			}

		})
	}
}

func TestBoundaryBuilder(t *testing.T) {
	for _, tt := range []struct {
		name         string
		pollInterval string
		pollDuration string

		expectedPollPeriods uint
		expectedBoundaries  []uint
	}{
		{
			name:         "poll every second, over 1 minute",
			pollInterval: "1s",
			pollDuration: "1m",

			expectedPollPeriods: 60,
			expectedBoundaries:  []uint{},
		},
		{
			name:         "poll every second, over 10 minutes",
			pollInterval: "1s",
			pollDuration: "10m",

			expectedPollPeriods: 600,
			expectedBoundaries: []uint{
				60, 90, 120, 150, 180, 210, 240, 270, 300, 330,
				360, 390, 420, 450, 480, 510, 540, 570, 599,
			},
		},
		{
			name:         "poll every second, over 20 minutes",
			pollInterval: "1s",
			pollDuration: "20m",

			expectedPollPeriods: 1200,
			expectedBoundaries: []uint{
				60, 90, 120, 150, 180, 210, 240, 270, 300, 330,
				360, 390, 420, 450, 480, 510, 540, 570,
				600, 660, 720, 780, 840, 900, 960, 1020,
				1080, 1140, 1199,
			},
		},
		{
			name:         "poll every 5 seconds, over 1 minute",
			pollInterval: "5s",
			pollDuration: "1m",

			expectedPollPeriods: 12,
			expectedBoundaries:  []uint{},
		},
		{
			name:         "poll every 5 seconds, over 10 minutes",
			pollInterval: "5s",
			pollDuration: "10m",

			expectedPollPeriods: 120,
			expectedBoundaries: []uint{
				12, 18, 24, 30, 36, 42, 48, 54, 60, 66,
				72, 78, 84, 90, 96, 102, 108, 114, 119,
			},
		},
		{
			name:         "poll every 5 seconds, over 20 minutes",
			pollInterval: "5s",
			pollDuration: "20m",

			expectedPollPeriods: 240,
			expectedBoundaries: []uint{
				12, 18, 24, 30, 36, 42, 48, 54, 60, 66,
				72, 78, 84, 90, 96, 102, 108, 114, 120,
				132, 144, 156, 168, 180, 192, 204, 216, 228, 239,
			},
		},
		{
			name:         "poll every 10 seconds, over 1 minute",
			pollInterval: "10s",
			pollDuration: "1m",

			expectedPollPeriods: 6,
			expectedBoundaries:  []uint{},
		},
		{
			name:         "poll every 10 seconds, over 10 minutes",
			pollInterval: "10s",
			pollDuration: "10m",

			expectedPollPeriods: 60,
			expectedBoundaries: []uint{
				6, 9, 12, 15, 18, 21, 24, 27, 30,
				33, 36, 39, 42, 45, 48, 51, 54, 57, 59,
			},
		},
		{
			name:         "poll every 10 seconds, over 20 minutes",
			pollInterval: "10s",
			pollDuration: "20m",

			expectedPollPeriods: 120,
			expectedBoundaries: []uint{
				6, 9, 12, 15, 18, 21, 24, 27, 30,
				33, 36, 39, 42, 45, 48, 51, 54, 57, 60,
				66, 72, 78, 84, 90, 96, 102, 108, 114, 119,
			},
		},
		{
			name:         "poll every 20 seconds, over 1 minute",
			pollInterval: "20s",
			pollDuration: "1m",

			expectedPollPeriods: 3,
			expectedBoundaries:  []uint{},
		},
		{
			name:         "poll every 20 seconds, over 10 minutes",
			pollInterval: "20s",
			pollDuration: "10m",

			expectedPollPeriods: 30,
			expectedBoundaries: []uint{
				3, 4, 6, 7, 9, 10, 12, 13, 15, 16,
				18, 19, 21, 22, 24, 25, 27, 28, 29,
			},
		},
		{
			name:         "poll every 20 seconds, over 20 minutes",
			pollInterval: "20s",
			pollDuration: "20m",

			expectedPollPeriods: 60,
			expectedBoundaries: []uint{
				3, 4, 6, 7, 9, 10, 12, 13, 15, 16,
				18, 19, 21, 22, 24, 25, 27, 28, 30,
				33, 36, 39, 42, 45, 48, 51, 54, 57, 59,
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			pollInterval, err := time.ParseDuration(tt.pollInterval)
			require.NoError(t, err, "error in specifying test poll interval")
			pollDuration, err := time.ParseDuration(tt.pollDuration)
			require.NoError(t, err, "error in specifying test poll duration")
			pollPeriods := endpoints.PollPeriods(pollInterval, pollDuration)

			require.Equal(t, tt.expectedPollPeriods, pollPeriods)
			boundaries := endpoints.BoundaryBuilder(pollInterval, pollDuration)
			require.Equal(t, tt.expectedBoundaries, boundaries)
		})
	}
}
