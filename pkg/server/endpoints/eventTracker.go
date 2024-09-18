package endpoints

import (
// 	"fmt"
	"slices"
	"time"
)

const INITIAL_POLL_COUNT uint = 10

type eventTracker struct {
	initialPolls uint
	pollPeriods  uint
	events       map[uint]*eventStats
	boundaries   []uint
}

type eventStats struct {
	hash  uint
	ticks uint
	polls uint
}

func PollPeriods(pollTime time.Duration, trackTime time.Duration) uint {
	if pollTime < (time.Duration(1) * time.Minute) {
		pollTime = time.Duration(1) * time.Minute
	}
	if trackTime < (time.Duration(1) * time.Minute) {
		trackTime = time.Duration(1) * time.Minute
	}
	return uint(1 + (trackTime - 1) / pollTime)
}

func BoundaryBuilder(pollTime time.Duration, trackTime time.Duration) []uint {
	pollPeriods := PollPeriods(pollTime, trackTime)

	pollBoundaries := make([]uint, 0)
	// number of polls in a minute
	pollsPerMinute := uint(time.Duration(1) * time.Minute / pollTime)
	// number of polls in ten minutes
	pollsPerTenMinutes := uint(time.Duration(10) * time.Minute / pollTime)

	// for first minute, poll at cacheReloadInterval
	pollBoundaries = append(pollBoundaries, pollsPerMinute)
	// next 9 minutes, poll at 1/2 minute
	currentBoundary := pollsPerMinute
	for currentBoundary < pollsPerTenMinutes {
		pollBoundaries = append(pollBoundaries, currentBoundary + (pollsPerMinute / 2))
		pollBoundaries = append(pollBoundaries, currentBoundary + pollsPerMinute)
		currentBoundary += pollsPerMinute
	}
	// rest of polling at 1 minute
	for currentBoundary < pollPeriods {
		pollBoundaries = append(pollBoundaries, currentBoundary + pollsPerMinute)
		currentBoundary += pollsPerMinute
	}
	// always poll at end of transaction timeout
	pollBoundaries = append(pollBoundaries, pollPeriods - 1)

	return pollBoundaries
}

func NewEventTracker(pollPeriods uint, boundaries []uint) *eventTracker {
	if pollPeriods < 1 {
		pollPeriods = 1
	}

	// cleanup boundaries into incrasing slice of no duplicates
	boundaryMap := make(map[uint]bool)
	filteredBounds := []uint{}
	for _, boundary := range boundaries {
		// trim duplicates and boundaries outside of polling range
		if _, found := boundaryMap[boundary]; !found && boundary < pollPeriods {
			boundaryMap[boundary] = true
			filteredBounds = append(filteredBounds, boundary)
		}
	}
	slices.Sort(filteredBounds)

	initialPolls := uint(0)
	switch {
	case boundaries == nil, len(filteredBounds) == 0:
		initialPolls = pollPeriods
	default:
		initialPolls = filteredBounds[0]
	}

	return &eventTracker{
		initialPolls: initialPolls,
		pollPeriods:  pollPeriods,
		boundaries:   filteredBounds,
		events:       make(map[uint]*eventStats),
	}
}

func (et *eventTracker) PollPeriods() uint {
	return et.pollPeriods
}

func (et *eventTracker) InitialPolls() uint {
	return et.initialPolls
}

func (et *eventTracker) PollBoundaries() []uint {
	return et.boundaries
}

func (et *eventTracker) Polls() uint {
	return et.initialPolls + uint(len(et.boundaries))
}

func (et *eventTracker) StartTracking(event uint) {
	et.events[event] = &eventStats{
		hash: hash(event),
		ticks: 0,
		polls: 0,
	}
}

func (et *eventTracker) StopTracking(event uint) {
	delete(et.events, event)
}


func (et *eventTracker) SelectEvents() []uint {
	// fmt.Print("polling events\n")
	pollList := make([]uint, 0)
	for event, _ := range et.events {
		eventStats := et.events[event]
		bucket := eventStats.polls - et.initialPolls
		// fmt.Printf("  event %d: %+v, bucket %d\n", event, eventStats, bucket)
		switch {
		case eventStats.polls < et.initialPolls:
			// fmt.Print("  initial poll range, adding\n")
			pollList = append(pollList, event)
			eventStats.polls++
		case bucket + 1 < uint(len(et.boundaries)):
			// fmt.Print("  not last range\n")
			bucketWidth := et.boundaries[1+bucket] - et.boundaries[bucket]
			bucketPosition := eventStats.hash % bucketWidth
			//fmt.Printf("event %d, hash %d, bucket %d\n", event, eventStats.hash, bucketPosition)
			if eventStats.ticks == et.boundaries[bucket] + bucketPosition {
				pollList = append(pollList, event)
			}
		case bucket < uint(len(et.boundaries)):
			// fmt.Print("  last range\n")
			bucketWidth := et.pollPeriods - et.boundaries[bucket]
			bucketPosition := eventStats.hash % bucketWidth
			//fmt.Printf("event %d, hash %d, bucket %d\n", event, eventStats.hash, bucketPosition)
			if eventStats.ticks == et.boundaries[bucket] + bucketPosition {
				pollList = append(pollList, event)
			}
		}
		eventStats.ticks++
	}
	return pollList
}

func (et *eventTracker) EventCount() uint {
	return uint(len(et.events))
}

func hash(event uint) uint {
	h := event
	h ^= h >> 16
	h *= 0x119de1f3
	h ^= h >> 15
	h *= 0x119de1f3
	h ^= h >> 16
	return h
}
