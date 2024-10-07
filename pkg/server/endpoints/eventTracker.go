package endpoints

import (
	"maps"
	"slices"
	"time"
)

/**
 * Tracks events as they indivicually walk through a list of event boundaries.
 *
 * An event track is defined with a set of boundaries, which are indexes to
 * virtual hash tables, with the event's hash determining the position within
 * that hash table where the event will be selected to be polled.
 * For eventTRackers that lack boundaries, or polls that exist prior to
 * boundaries, the event is always polled.
 */
type eventTracker struct {
	/* Times the event is polled before entering a boundary */
	initialPolls uint
	/* Times the event is polled */
	pollPeriods uint
	/* Per event context of each event's walk across the boudaries */
	events map[uint]*eventStats
	/* The leading index of boundaries in which an event should only report once */
	boundaries []uint
}

/**
 * Tracks event context in its walk of the event boundaries.
 */
type eventStats struct {
	/* The event's hash for hash table calcuations */
	hash uint
	/* The number of times the event was considered for polling */
	ticks uint
	/* The number of times the event was selected for polling */
	polls uint
}

/**
 * A utility function to get the number of PollTimes (ticks) in an interval.
 *
 * Subsecond inputs are adjusted to a minimum value one second.
 *
 * @returns One tick, or the smallest number of ticks that just exceeds the trackTime..
 */
func PollPeriods(pollTime time.Duration, trackTime time.Duration) uint {
	if pollTime < (time.Duration(1) * time.Second) {
		pollTime = time.Duration(1) * time.Second
	}
	if trackTime < (time.Duration(1) * time.Second) {
		trackTime = time.Duration(1) * time.Second
	}
	return uint(1 + (trackTime-1)/pollTime)
}

/**
 * The default boundary strategy.
 *
 * Poll everything at poll rate for at least one minute, then poll everything
 * twice a minute for 9 minute, then onece a minute for rest of time, with a
 * guaranteed poll just before no longer tracking.
 *
 * This strategy is completely arbitrary.  Future boundary building approaches
 * may be added if necessary, like linear (5, 10, 15, 20, 25, 30, 35, ...),
 * exponential (2, 4, 8, 16, 32, 64, 128, 256, ...), exponential capped at a
 * limit (2, 4, 8, 16, 30, 60, 90, 120, ...), cube root, etc.
 */
func BoundaryBuilder(pollTime time.Duration, trackTime time.Duration) []uint {
	pollPeriods := PollPeriods(pollTime, trackTime)

	// number of polls in a minute
	pollsPerMinute := uint(time.Duration(1) * time.Minute / pollTime)
	// number of polls in ten minutes
	pollsPerTenMinutes := uint(time.Duration(10) * time.Minute / pollTime)

	// initialize poll boundaries one minute out
	boundaries := make(map[uint]struct{})
	currentBoundary := pollsPerMinute
	for currentBoundary < pollPeriods {
		if currentBoundary < pollsPerTenMinutes {
			boundaries[currentBoundary] = struct{}{}
			boundaries[currentBoundary+(pollsPerMinute/2)] = struct{}{}
		} else {
			boundaries[currentBoundary] = struct{}{}
		}
		currentBoundary += pollsPerMinute
	}
	if 0 < len(boundaries) {
		boundaries[pollPeriods-1] = struct{}{}
	}

	boundaryList := slices.Collect(maps.Keys(boundaries))
	slices.Sort(boundaryList)
	if boundaryList == nil {
		boundaryList = []uint{}
	}

	return boundaryList
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

/**
 * Starts tracking an event's walk through the boundaries.
 */
func (et *eventTracker) StartTracking(event uint) {
	et.events[event] = &eventStats{
		hash:  hash(event),
		ticks: 0,
		polls: 0,
	}
}

/**
 * Remove an event from the tracker.
 *
 * Events not explicitly removed will remove themselves
 * after SelectEvents has been called PollPeriods() number
 * of times.
 */
func (et *eventTracker) StopTracking(event uint) {
	delete(et.events, event)
}

/**
 * Selects the events one should pool for the next poll cycle.
 *
 * This algorithm determines if the events should be polled, and
 * increments each event's time, allowing every event to act on
 * the time the event was inserted into eventTracker.
 *
 * The event's boundary Index is computed, and if it is below the
 * number of initial polls, the event is polled without further
 * analysis.
 *
 * If the boundary index is inside a defined boundary, the width
 * of the boundary is computed and the event's position within
 * the virtual hash table is computed from "hash(event) % width".
 * As the hash and width are stable, an event will always remain
 * in the same slot within a boundary.
 *
 * If the event's ticks (the events local sense of time) match
 * the event's slot within the boundary, the event is added to
 * the poll list.
 */
func (et *eventTracker) SelectEvents() []uint {
	pollList := make([]uint, 0)
	for event, _ := range et.events {
		if et.events[event].ticks >= et.pollPeriods {
			et.StopTracking(event)
			continue
		}
		eventStats := et.events[event]
		boundaryIndex := eventStats.polls - et.initialPolls
		switch {
		// before boundaries
		case eventStats.polls < et.initialPolls:
			pollList = append(pollList, event)
			eventStats.polls++
		// between boundaries
		case boundaryIndex+1 < uint(len(et.boundaries)):
			boundaryWidth := et.boundaries[1+boundaryIndex] - et.boundaries[boundaryIndex]
			boundaryPosition := eventStats.hash % boundaryWidth
			if eventStats.ticks == et.boundaries[boundaryIndex]+boundaryPosition {
				pollList = append(pollList, event)
				eventStats.polls++
			}
		// last boundary
		case boundaryIndex < uint(len(et.boundaries)):
			boundaryWidth := et.pollPeriods - et.boundaries[boundaryIndex]
			boundaryPosition := eventStats.hash % boundaryWidth
			if eventStats.ticks == et.boundaries[boundaryIndex]+boundaryPosition {
				pollList = append(pollList, event)
				eventStats.polls++
			}
		}
		eventStats.ticks++
	}
	return pollList
}

/**
 * Returns the count of events being tracked.
 *
 * @return the events being tracked.
 */
func (et *eventTracker) EventCount() uint {
	return uint(len(et.events))
}

/**
 * A hash function for uint.
 *
 * The slots within a boundary are conceptually a hash table, even
 * though the hash table doesn't exist as an struct.  This means that
 * each event being polled must distribute within the conceptual hash
 * table evenly, or the conceptual hash table will only have entries in
 * a subset of slots.
 *
 * This hashing algorithm is the modification of a number of algorithms
 * previously found on the internet.  It avoids the factorization problem
 * (even events only go into even slots) by repeatedly mixing high order
 * bits into the low order bits ( h^h >> (number)).  The high order bits
 * are primarily set by the low order bits repeatedly by multipliation with
 * a number designed to mix bits deterministicly for better hash dispersion.
 */
func hash(event uint) uint {
	h := event
	h ^= h >> 16
	h *= 0x119de1f3
	h ^= h >> 15
	h *= 0x119de1f3
	h ^= h >> 16
	return h
}
