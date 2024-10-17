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
			pollInterval: time.Minute,
			pollDuration: time.Duration(0) * time.Minute,

			expectedPollPeriods: 1,
		},
		{
			name:         "polling always polls at least once, even for negative durations",
			pollInterval: time.Minute,
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
			pollInterval: time.Minute,
			pollDuration: time.Minute * time.Duration(2),

			expectedPollPeriods: 2,
		},
		{
			name:         "polling every minute of an hours",
			pollInterval: time.Minute,
			pollDuration: time.Hour,

			expectedPollPeriods: 60,
		},
		{
			name:         "polling rounds up",
			pollInterval: time.Minute * time.Duration(3),
			pollDuration: time.Minute * time.Duration(10),

			expectedPollPeriods: 4,
		},
	} {
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

		expectedPollPeriods uint
		expectedPolls       uint
	}{
		{
			name:        "polling always polls at least once",
			pollPeriods: 0,

			expectedPollPeriods: 1,
			expectedPolls:       1,
		},
		{
			name:        "polling once",
			pollPeriods: 1,

			expectedPollPeriods: 1,
			expectedPolls:       1,
		},
		{
			name:        "polling twice",
			pollPeriods: 2,

			expectedPollPeriods: 2,
			expectedPolls:       2,
		},
		{
			name:        "polling three times",
			pollPeriods: 3,

			expectedPollPeriods: 3,
			expectedPolls:       3,
		},
		{
			name:        "polling 120 times",
			pollPeriods: 120,

			expectedPollPeriods: 120,
			expectedPolls:       120,
		},
		{
			name:        "polling 600 times",
			pollPeriods: 600,

			expectedPollPeriods: 600,
			expectedPolls:       600,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			eventTracker := endpoints.NewEventTracker(tt.pollPeriods)

			require.Equal(t, tt.expectedPollPeriods, eventTracker.PollPeriods(), "expecting %d poll periods; but, %d poll periods reported", eventTracker.PollPeriods(), tt.expectedPollPeriods)

			require.Equal(t, tt.expectedPolls, eventTracker.Polls(), "polling each element %d times, when expecting %d times", tt.expectedPolls, eventTracker.Polls())
		})
	}
}

func TestEvenTrackerPolling(t *testing.T) {
	for _, tt := range []struct {
		name        string
		pollPeriods uint

		trackEvents    [][]uint
		expectedPolls  uint
		expectedEvents [][]uint
	}{
		{
			name:        "every event is polled at least once, even when zero polling periods",
			pollPeriods: 0,
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
		t.Run(tt.name, func(t *testing.T) {
			eventTracker := endpoints.NewEventTracker(tt.pollPeriods)
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
