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
			name:         "minimum poll interval of one minute",
			pollInterval: time.Duration(20) * time.Second,
			pollDuration: time.Duration(10) * time.Minute,

			expectedPollPeriods: 10,
		},
		{
			name:         "minimum poll interval of one minute, even for negative intervals",
			pollInterval: time.Duration(-1) * time.Minute,
			pollDuration: time.Duration(10) * time.Minute,

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

/*
 0 1 2 3 4 5 (pollPeriods)
 0     3     (boundaries)
 0 0 0 1 1 1 (bucket number)
 3 3 3 3 3 3 (bucket width)

 0 3 0 0 3 0 (timeslots to poll event 3)
 3 3 3 3 3 3 (every slot is polled)

 pollEvent(3)
 hash := hash(3) # hash must distribute well
 poll within the bucket = 34234 % (bucket width)
 */

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
				events := eventTracker.PollEvents()
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
		name           string
		pollPeriods    uint

		startEvent     uint
		eventIncrement uint
		eventCount     uint

		expectedSlotCount uint
		permissibleCountError uint
	}{
		{
			name: "increment by 2 (offset 0) events distribute fairly across 2 slots",
			pollPeriods: 2,
			startEvent: 0,
			eventIncrement: 2,
			eventCount: 1000,

			expectedSlotCount: 500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 2 (offset 1) events distribute fairly across 2 slots",
			pollPeriods: 2,
			startEvent: 0,
			eventIncrement: 2,
			eventCount: 1000,

			expectedSlotCount: 500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 3 (offset 0) events distribute fairly across 2 slots",
			pollPeriods: 2,
			startEvent: 0,
			eventIncrement: 3,
			eventCount: 1000,

			expectedSlotCount: 500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 3 (offset 1) events distribute fairly across 2 slots",
			pollPeriods: 2,
			startEvent: 1,
			eventIncrement: 3,
			eventCount: 1000,

			expectedSlotCount: 500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 3 (offset 2) events distribute fairly across 2 slots",
			pollPeriods: 2,
			startEvent: 2,
			eventIncrement: 3,
			eventCount: 1000,

			expectedSlotCount: 500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 4 (offset 0) events distribute fairly across 2 slots",
			pollPeriods: 2,
			startEvent: 0,
			eventIncrement: 4,
			eventCount: 1000,

			expectedSlotCount: 500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 4 (offset 1) events distribute fairly across 2 slots",
			pollPeriods: 2,
			startEvent: 1,
			eventIncrement: 4,
			eventCount: 1000,

			expectedSlotCount: 500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 4 (offset 2) events distribute fairly across 2 slots",
			pollPeriods: 2,
			startEvent: 2,
			eventIncrement: 4,
			eventCount: 1000,

			expectedSlotCount: 500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 4 (offset 3) events distribute fairly across 2 slots",
			pollPeriods: 2,
			startEvent: 3,
			eventIncrement: 4,
			eventCount: 1000,

			expectedSlotCount: 500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 5 (offset 0) events distribute fairly across 2 slots",
			pollPeriods: 2,
			startEvent: 0,
			eventIncrement: 5,
			eventCount: 1000,

			expectedSlotCount: 500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 5 (offset 1) events distribute fairly across 2 slots",
			pollPeriods: 2,
			startEvent: 1,
			eventIncrement: 5,
			eventCount: 1000,

			expectedSlotCount: 500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 5 (offset 2) events distribute fairly across 2 slots",
			pollPeriods: 2,
			startEvent: 2,
			eventIncrement: 5,
			eventCount: 1000,

			expectedSlotCount: 500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 5 (offset 3) events distribute fairly across 2 slots",
			pollPeriods: 2,
			startEvent: 3,
			eventIncrement: 5,
			eventCount: 1000,

			expectedSlotCount: 500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 5 (offset 4) events distribute fairly across 2 slots",
			pollPeriods: 2,
			startEvent: 4,
			eventIncrement: 5,
			eventCount: 1000,

			expectedSlotCount: 500,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 2 (offset 0) events distribute fairly across 3 slots",
			pollPeriods: 3,
			startEvent: 0,
			eventIncrement: 2,
			eventCount: 1000,

			expectedSlotCount: 333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 2 (offset 1) events distribute fairly across 3 slots",
			pollPeriods: 3,
			startEvent: 0,
			eventIncrement: 2,
			eventCount: 1000,

			expectedSlotCount: 333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 3 (offset 0) events distribute fairly across 3 slots",
			pollPeriods: 3,
			startEvent: 0,
			eventIncrement: 3,
			eventCount: 1000,

			expectedSlotCount: 333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 3 (offset 1) events distribute fairly across 3 slots",
			pollPeriods: 3,
			startEvent: 1,
			eventIncrement: 3,
			eventCount: 1000,

			expectedSlotCount: 333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 3 (offset 2) events distribute fairly across 3 slots",
			pollPeriods: 3,
			startEvent: 2,
			eventIncrement: 3,
			eventCount: 1000,

			expectedSlotCount: 333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 4 (offset 0) events distribute fairly across 3 slots",
			pollPeriods: 3,
			startEvent: 0,
			eventIncrement: 4,
			eventCount: 1000,

			expectedSlotCount: 333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 4 (offset 1) events distribute fairly across 3 slots",
			pollPeriods: 3,
			startEvent: 1,
			eventIncrement: 4,
			eventCount: 1000,

			expectedSlotCount: 333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 4 (offset 2) events distribute fairly across 3 slots",
			pollPeriods: 3,
			startEvent: 2,
			eventIncrement: 4,
			eventCount: 1000,

			expectedSlotCount: 333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 4 (offset 3) events distribute fairly across 3 slots",
			pollPeriods: 3,
			startEvent: 3,
			eventIncrement: 4,
			eventCount: 1000,

			expectedSlotCount: 333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 5 (offset 0) events distribute fairly across 3 slots",
			pollPeriods: 3,
			startEvent: 0,
			eventIncrement: 5,
			eventCount: 1000,

			expectedSlotCount: 333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 5 (offset 1) events distribute fairly across 3 slots",
			pollPeriods: 3,
			startEvent: 1,
			eventIncrement: 5,
			eventCount: 1000,

			expectedSlotCount: 333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 5 (offset 2) events distribute fairly across 3 slots",
			pollPeriods: 3,
			startEvent: 2,
			eventIncrement: 5,
			eventCount: 1000,

			expectedSlotCount: 333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 5 (offset 3) events distribute fairly across 3 slots",
			pollPeriods: 3,
			startEvent: 3,
			eventIncrement: 5,
			eventCount: 1000,

			expectedSlotCount: 333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 5 (offset 4) events distribute fairly across 3 slots",
			pollPeriods: 3,
			startEvent: 4,
			eventIncrement: 5,
			eventCount: 1000,

			expectedSlotCount: 333,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 2 (offset 0) events distribute fairly across 4 slots",
			pollPeriods: 4,
			startEvent: 0,
			eventIncrement: 2,
			eventCount: 1000,

			expectedSlotCount: 250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 2 (offset 1) events distribute fairly across 4 slots",
			pollPeriods: 4,
			startEvent: 0,
			eventIncrement: 2,
			eventCount: 1000,

			expectedSlotCount: 250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 3 (offset 0) events distribute fairly across 4 slots",
			pollPeriods: 4,
			startEvent: 0,
			eventIncrement: 3,
			eventCount: 1000,

			expectedSlotCount: 250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 3 (offset 1) events distribute fairly across 4 slots",
			pollPeriods: 4,
			startEvent: 1,
			eventIncrement: 3,
			eventCount: 1000,

			expectedSlotCount: 250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 3 (offset 2) events distribute fairly across 4 slots",
			pollPeriods: 4,
			startEvent: 2,
			eventIncrement: 3,
			eventCount: 1000,

			expectedSlotCount: 250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 4 (offset 0) events distribute fairly across 4 slots",
			pollPeriods: 4,
			startEvent: 0,
			eventIncrement: 4,
			eventCount: 1000,

			expectedSlotCount: 250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 4 (offset 1) events distribute fairly across 4 slots",
			pollPeriods: 4,
			startEvent: 1,
			eventIncrement: 4,
			eventCount: 1000,

			expectedSlotCount: 250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 4 (offset 2) events distribute fairly across 4 slots",
			pollPeriods: 4,
			startEvent: 2,
			eventIncrement: 4,
			eventCount: 1000,

			expectedSlotCount: 250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 4 (offset 3) events distribute fairly across 4 slots",
			pollPeriods: 4,
			startEvent: 3,
			eventIncrement: 4,
			eventCount: 1000,

			expectedSlotCount: 250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 5 (offset 0) events distribute fairly across 4 slots",
			pollPeriods: 4,
			startEvent: 0,
			eventIncrement: 5,
			eventCount: 1000,

			expectedSlotCount: 250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 5 (offset 1) events distribute fairly across 4 slots",
			pollPeriods: 4,
			startEvent: 1,
			eventIncrement: 5,
			eventCount: 1000,

			expectedSlotCount: 250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 5 (offset 2) events distribute fairly across 4 slots",
			pollPeriods: 4,
			startEvent: 2,
			eventIncrement: 5,
			eventCount: 1000,

			expectedSlotCount: 250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 5 (offset 3) events distribute fairly across 4 slots",
			pollPeriods: 4,
			startEvent: 3,
			eventIncrement: 5,
			eventCount: 1000,

			expectedSlotCount: 250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 5 (offset 4) events distribute fairly across 4 slots",
			pollPeriods: 4,
			startEvent: 4,
			eventIncrement: 5,
			eventCount: 1000,

			expectedSlotCount: 250,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 2 (offset 0) events distribute fairly across 5 slots",
			pollPeriods: 5,
			startEvent: 0,
			eventIncrement: 2,
			eventCount: 1000,

			expectedSlotCount: 200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 2 (offset 1) events distribute fairly across 5 slots",
			pollPeriods: 5,
			startEvent: 0,
			eventIncrement: 2,
			eventCount: 1000,

			expectedSlotCount: 200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 3 (offset 0) events distribute fairly across 5 slots",
			pollPeriods: 5,
			startEvent: 0,
			eventIncrement: 3,
			eventCount: 1000,

			expectedSlotCount: 200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 3 (offset 1) events distribute fairly across 5 slots",
			pollPeriods: 5,
			startEvent: 1,
			eventIncrement: 3,
			eventCount: 1000,

			expectedSlotCount: 200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 3 (offset 2) events distribute fairly across 5 slots",
			pollPeriods: 5,
			startEvent: 2,
			eventIncrement: 3,
			eventCount: 1000,

			expectedSlotCount: 200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 4 (offset 0) events distribute fairly across 5 slots",
			pollPeriods: 5,
			startEvent: 0,
			eventIncrement: 4,
			eventCount: 1000,

			expectedSlotCount: 200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 4 (offset 1) events distribute fairly across 5 slots",
			pollPeriods: 5,
			startEvent: 1,
			eventIncrement: 4,
			eventCount: 1000,

			expectedSlotCount: 200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 4 (offset 2) events distribute fairly across 5 slots",
			pollPeriods: 5,
			startEvent: 2,
			eventIncrement: 4,
			eventCount: 1000,

			expectedSlotCount: 200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 4 (offset 3) events distribute fairly across 5 slots",
			pollPeriods: 5,
			startEvent: 3,
			eventIncrement: 4,
			eventCount: 1000,

			expectedSlotCount: 200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 5 (offset 0) events distribute fairly across 5 slots",
			pollPeriods: 5,
			startEvent: 0,
			eventIncrement: 5,
			eventCount: 1000,

			expectedSlotCount: 200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 5 (offset 1) events distribute fairly across 5 slots",
			pollPeriods: 5,
			startEvent: 1,
			eventIncrement: 5,
			eventCount: 1000,

			expectedSlotCount: 200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 5 (offset 2) events distribute fairly across 5 slots",
			pollPeriods: 5,
			startEvent: 2,
			eventIncrement: 5,
			eventCount: 1000,

			expectedSlotCount: 200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 5 (offset 3) events distribute fairly across 5 slots",
			pollPeriods: 5,
			startEvent: 3,
			eventIncrement: 5,
			eventCount: 1000,

			expectedSlotCount: 200,
			permissibleCountError: 50, // 5% of 1000
		},
		{
			name: "increment by 5 (offset 4) events distribute fairly across 5 slots",
			pollPeriods: 5,
			startEvent: 4,
			eventIncrement: 5,
			eventCount: 1000,

			expectedSlotCount: 200,
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
				events := eventTracker.PollEvents()
				slotCount[pollPeriod] = uint(len(events))
				t.Logf("pollPeriod %d, count = %d", pollPeriod, slotCount[pollPeriod])
			}
			for slot, count := range slotCount {
				require.LessOrEqual(t, tt.expectedSlotCount - tt.permissibleCountError, count,
					"for slot %d, expecting at least %d polls, but received %d polls",
					slot, tt.expectedSlotCount - tt.permissibleCountError, count)
				require.GreaterOrEqual(t, tt.expectedSlotCount + tt.permissibleCountError, count,
					"for slot %d, expecting no more than %d polls, but received %d polls",
					slot, tt.expectedSlotCount + tt.permissibleCountError, count)
			}

		})
	}
}
