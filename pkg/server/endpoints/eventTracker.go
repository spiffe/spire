package endpoints

import (
	"sync"
	"time"

	"github.com/spiffe/spire/pkg/common/util"
)

type eventTracker struct {
	pollPeriods uint

	events map[uint]uint

	pool sync.Pool
}

func PollPeriods(pollTime time.Duration, trackTime time.Duration) uint {
	if pollTime < time.Second {
		pollTime = time.Second
	}
	if trackTime < time.Second {
		trackTime = time.Second
	}
	return util.MustCast[uint](1 + (trackTime-1)/pollTime)
}

func NewEventTracker(pollPeriods uint) *eventTracker {
	if pollPeriods < 1 {
		pollPeriods = 1
	}

	return &eventTracker{
		pollPeriods: pollPeriods,
		events:      make(map[uint]uint),
		pool: sync.Pool{
			New: func() any {
				// See https://staticcheck.dev/docs/checks#SA6002.
				return new([]uint)
			},
		},
	}
}

func (et *eventTracker) PollPeriods() uint {
	return et.pollPeriods
}

func (et *eventTracker) Polls() uint {
	return et.pollPeriods
}

func (et *eventTracker) StartTracking(event uint) {
	et.events[event] = 0
}

func (et *eventTracker) StopTracking(event uint) {
	delete(et.events, event)
}

func (et *eventTracker) SelectEvents() []uint {
	pollList := *et.pool.Get().(*[]uint)
	for event := range et.events {
		if et.events[event] >= et.pollPeriods {
			et.StopTracking(event)
			continue
		}
		pollList = append(pollList, event)
		et.events[event]++
	}
	return pollList
}

func (et *eventTracker) FreeEvents(events []uint) {
	events = events[:0]
	et.pool.Put(&events)
}

func (et *eventTracker) EventCount() int {
	return len(et.events)
}
