package ratelimit

import (
	"context"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"golang.org/x/time/rate"
)

// DefaultGCInterval is the default interval at which inactive limiters are
// garbage collected.
const DefaultGCInterval = time.Minute

// Limiter represents the rate limiter functionality.
type Limiter interface {
	WaitN(ctx context.Context, n int) error
	AllowN(now time.Time, n int) bool
	Limit() rate.Limit
	Burst() int
}

// rateLimiter wraps rate.Limiter to implement the Limiter interface.
type rateLimiter struct {
	*rate.Limiter
}

func (l *rateLimiter) AllowN(now time.Time, n int) bool {
	return l.Limiter.AllowN(now, n)
}

func (l *rateLimiter) WaitN(ctx context.Context, n int) error {
	return l.Limiter.WaitN(ctx, n)
}

// NewLimiter creates a new rate limiter with the given limit and burst.
func NewLimiter(limit rate.Limit, burst int) Limiter {
	return &rateLimiter{Limiter: rate.NewLimiter(limit, burst)}
}

// Map is a thread-safe map of rate limiters keyed by string.
// It uses a two-generation garbage collection pattern to evict inactive limiters.
type Map struct {
	limit      int
	gcInterval time.Duration
	clock      clock.Clock
	creator    func(limit rate.Limit, burst int) Limiter

	mtx      sync.RWMutex
	previous map[string]Limiter
	current  map[string]Limiter
	lastGC   time.Time
}

// NewMap creates a new Map with the given limit and GC interval.
func NewMap(limit int, gcInterval time.Duration, clock clock.Clock) *Map {
	return NewMapWithCreator(limit, gcInterval, clock, NewLimiter)
}

// NewMapWithCreator creates a new Map with the given limit, GC interval, and
// custom limiter creator.
func NewMapWithCreator(limit int, gcInterval time.Duration, clock clock.Clock, creator func(limit rate.Limit, burst int) Limiter) *Map {
	return &Map{
		limit:      limit,
		gcInterval: gcInterval,
		clock:      clock,
		creator:    creator,
		current:    make(map[string]Limiter),
		lastGC:     clock.Now(),
	}
}

// Get returns the limiter for the given key. If a limiter does not exist,
// it is created.
func (m *Map) Get(key string) Limiter {
	m.mtx.RLock()
	limiter, ok := m.current[key]
	if ok {
		m.mtx.RUnlock()
		return limiter
	}
	m.mtx.RUnlock()

	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Check current again in case another goroutine created it while we were
	// upgrading the lock.
	if limiter, ok = m.current[key]; ok {
		return limiter
	}

	// Check previous to see if it was moved to previous by a recent GC.
	if limiter, ok = m.previous[key]; ok {
		m.current[key] = limiter
		delete(m.previous, key)
		return limiter
	}

	// If it's time for GC, move current to previous and start a new current.
	now := m.clock.Now()
	if now.Sub(m.lastGC) >= m.gcInterval {
		m.previous = m.current
		m.current = make(map[string]Limiter)
		m.lastGC = now
	}

	limiter = m.creator(rate.Limit(m.limit), m.limit)
	m.current[key] = limiter
	return limiter
}
