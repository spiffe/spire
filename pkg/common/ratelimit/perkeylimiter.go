package ratelimit

import (
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
)

const (
	// GCInterval is the interval at which per-key limiters are garbage
	// collected. Keys not accessed within two GC intervals are reclaimed.
	GCInterval = time.Minute
)

// PerKeyLimiter maintains per-key rate limiters using a two-generation garbage
// collection pattern. Keys that are not accessed within two GC intervals have
// their limiters reclaimed.
type PerKeyLimiter struct {
	newLimiter func() Limiter
	clock      clock.Clock

	mtx sync.RWMutex

	// previous holds all the limiters that were current at the last GC.
	previous map[string]Limiter

	// current holds all the limiters that have been created or promoted
	// from previous since the last GC.
	current map[string]Limiter

	// lastGC is the time of the last garbage collection.
	lastGC time.Time
}

// Option configures a PerKeyLimiter.
type Option func(*PerKeyLimiter)

// WithClock sets the clock used for time-based operations. Useful for testing.
func WithClock(c clock.Clock) Option {
	return func(l *PerKeyLimiter) {
		l.clock = c
	}
}

// NewPerKeyLimiter creates a new PerKeyLimiter with the given limiter factory
// and options.
func NewPerKeyLimiter(newLimiter func() Limiter, opts ...Option) *PerKeyLimiter {
	l := &PerKeyLimiter{
		newLimiter: newLimiter,
		clock:      clock.New(),
		current:    make(map[string]Limiter),
	}
	for _, opt := range opts {
		opt(l)
	}
	l.lastGC = l.clock.Now()
	return l
}

// Now returns the current time according to the configured clock.
func (l *PerKeyLimiter) Now() time.Time {
	return l.clock.Now()
}

// GetLimiter returns the rate limiter for the given key, creating one if
// necessary and performing garbage collection as needed.
func (l *PerKeyLimiter) GetLimiter(key string) Limiter {
	l.mtx.RLock()
	limiter, ok := l.current[key]
	if ok {
		l.mtx.RUnlock()
		return limiter
	}
	l.mtx.RUnlock()

	// A limiter does not exist for that key.
	l.mtx.Lock()
	defer l.mtx.Unlock()

	// Check the "current" entries in case another goroutine raced on this key.
	if limiter, ok = l.current[key]; ok {
		return limiter
	}

	// Then check the "previous" entries to see if a limiter exists for this
	// key as of the last GC. If so, move it to current and return it.
	if limiter, ok = l.previous[key]; ok {
		l.current[key] = limiter
		delete(l.previous, key)
		return limiter
	}

	// There is no limiter for this key. Before we create one, we should see
	// if we need to do GC.
	now := l.clock.Now()
	if now.Sub(l.lastGC) >= GCInterval {
		l.previous = l.current
		l.current = make(map[string]Limiter)
		l.lastGC = now
	}

	limiter = l.newLimiter()
	l.current[key] = limiter
	return limiter
}
