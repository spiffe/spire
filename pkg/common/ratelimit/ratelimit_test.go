package ratelimit

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

func TestMap(t *testing.T) {
	c := clock.NewMock()
	const limit = 10
	const gcInterval = time.Minute

	m := NewMap(limit, gcInterval, c)

	// Get a limiter for a key
	l1 := m.Get("key1")
	assert.NotNil(t, l1)
	assert.Equal(t, rate.Limit(limit), l1.Limit())
	assert.Equal(t, limit, l1.Burst())

	// Getting the same key returns the same limiter
	l1Again := m.Get("key1")
	assert.Same(t, l1, l1Again)

	// Getting a different key returns a different limiter
	l2 := m.Get("key2")
	assert.NotSame(t, l1, l2)

	// Advance time, but not enough for GC
	c.Add(gcInterval / 2)
	l1Still := m.Get("key1")
	assert.Same(t, l1, l1Still)

	// Advance time enough for GC
	c.Add(gcInterval)
	// key1 should be in previous now. Getting it should move it to current.
	l1AfterGC := m.Get("key1")
	assert.Same(t, l1, l1AfterGC)

	// key2 should still be in previous. 
	// Get a new key to trigger GC (actually GC happens in NewMap and when a *new* key is added and interval passed)
	// Wait, the logic in Get:
	/*
	now := m.clock.Now()
	if now.Sub(m.lastGC) >= m.gcInterval {
		m.previous = m.current
		m.current = make(map[string]Limiter)
		m.lastGC = now
	}
	*/
	// This only happens BEFORE a NEW limiter is created.
	// So let's add a NEW key.
	l3 := m.Get("key3")
	assert.NotSame(t, l1, l3)
	
	// Now key2 should be in previous (it was in current, then moved to previous when l3 was added)
	// Wait, when l3 was added, m.lastGC was updated, m.current was cleared, m.previous was set to old current.
	// So l2 is in previous.
	// Let's add another interval and a new key to trigger another GC.
	c.Add(gcInterval + 1)
	m.Get("key4")
	
	// Now key2 should be gone from previous.
	// Getting key2 should return a NEW limiter.
	l2New := m.Get("key2")
	assert.NotSame(t, l2, l2New)
}

func TestMapConcurrency(t *testing.T) {
	c := clock.NewMock()
	m := NewMap(10, time.Minute, c)
	var wg sync.WaitGroup
	const workers = 100
	const iterations = 100

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				m.Get("key")
			}
		}()
	}
	wg.Wait()
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(rate.Limit(0), 1)
	assert.True(t, l.AllowN(time.Now(), 1))
	assert.False(t, l.AllowN(time.Now(), 1))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	// Should fail because burst is 1 and we just used it.
	err := l.WaitN(ctx, 1)
	assert.Error(t, err)
}
