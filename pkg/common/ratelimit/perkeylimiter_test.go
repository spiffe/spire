package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"

	testclock "github.com/spiffe/spire/test/clock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

func newTestLimiterFactory(limit int) func() Limiter {
	return func() Limiter {
		return rate.NewLimiter(rate.Limit(limit), limit)
	}
}

func TestPerKeyLimiterBasic(t *testing.T) {
	l := NewPerKeyLimiter(newTestLimiterFactory(2))

	lim := l.GetLimiter("key1")
	// First two events are allowed (burst=2).
	assert.True(t, lim.AllowN(time.Now(), 1))
	assert.True(t, lim.AllowN(time.Now(), 1))
	// Third event is denied.
	assert.False(t, lim.AllowN(time.Now(), 1))
}

func TestPerKeyLimiterIndependence(t *testing.T) {
	l := NewPerKeyLimiter(newTestLimiterFactory(1))

	// Different keys have independent token buckets.
	lim1 := l.GetLimiter("key1")
	lim2 := l.GetLimiter("key2")
	assert.True(t, lim1.AllowN(time.Now(), 1))
	assert.True(t, lim2.AllowN(time.Now(), 1))
	// Both keys are now exhausted.
	assert.False(t, lim1.AllowN(time.Now(), 1))
	assert.False(t, lim2.AllowN(time.Now(), 1))
}

func TestPerKeyLimiterSameKeyReturnsSameLimiter(t *testing.T) {
	l := NewPerKeyLimiter(newTestLimiterFactory(1))

	lim1 := l.GetLimiter("key1")
	lim2 := l.GetLimiter("key1")
	assert.Same(t, lim1, lim2)
}

func TestPerKeyLimiterGC(t *testing.T) {
	mockClk := testclock.NewMock(t)
	l := NewPerKeyLimiter(newTestLimiterFactory(1), WithClock(mockClk))

	// Create and exhaust key1.
	lim := l.GetLimiter("key1")
	assert.True(t, lim.AllowN(mockClk.Now(), 1))
	assert.False(t, lim.AllowN(mockClk.Now(), 1))

	// Advance past the GC interval and trigger GC by accessing key2.
	// key1 moves from current to previous.
	mockClk.Add(GCInterval)
	l.GetLimiter("key2")

	// Advance past the GC interval again and trigger GC by accessing key3.
	// key1 (in previous) is dropped entirely.
	mockClk.Add(GCInterval)
	l.GetLimiter("key3")

	// key1 has been GC'd. A new limiter is created with a fresh token bucket.
	lim = l.GetLimiter("key1")
	assert.True(t, lim.AllowN(mockClk.Now(), 1))
}

func TestPerKeyLimiterPreviousPreservation(t *testing.T) {
	mockClk := testclock.NewMock(t)
	l := NewPerKeyLimiter(newTestLimiterFactory(1), WithClock(mockClk))

	// Create limiters for key1 and key2.
	l.GetLimiter("key1")
	l.GetLimiter("key2")

	// Advance past GC interval and trigger GC via key3.
	// key1 and key2 move to previous.
	mockClk.Add(GCInterval)
	l.GetLimiter("key3")

	// Access key1 - it gets promoted from previous to current (same limiter).
	lim1Before := l.GetLimiter("key1")

	// Advance past GC interval again and trigger GC via key4.
	// key2 (in previous) is dropped. key1 and key3 move to previous.
	mockClk.Add(GCInterval)
	l.GetLimiter("key4")

	// key1 was promoted so it's still alive (moved to previous, not dropped).
	lim1After := l.GetLimiter("key1")
	assert.Same(t, lim1Before, lim1After)

	// key2 is gone; accessing it creates a fresh limiter.
	lim2 := l.GetLimiter("key2")
	assert.True(t, lim2.AllowN(mockClk.Now(), 1))
}

func TestPerKeyLimiterConcurrency(t *testing.T) {
	const goroutines = 50
	const callsPerGoroutine = 200

	l := NewPerKeyLimiter(newTestLimiterFactory(10))

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			key := fmt.Sprintf("key:%d", id%5)
			for j := 0; j < callsPerGoroutine; j++ {
				lim := l.GetLimiter(key)
				lim.AllowN(time.Now(), 1)
			}
		}(i)
	}
	wg.Wait()
}
