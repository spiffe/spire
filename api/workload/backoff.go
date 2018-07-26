package workload

import (
	"sync"
	"time"
)

const backoffStartDuration = 1 * time.Second

// backoff implements a backoff timer used to space out retries against
// the workload api.
type backoff struct {
	mtx     *sync.Mutex
	current time.Duration
	timeout time.Duration
}

// newBackoff creates a new backoff struct with the requested timeout applied.
func newBackoff(timeout time.Duration) *backoff {
	return &backoff{
		mtx:     new(sync.Mutex),
		current: backoffStartDuration,
		timeout: timeout,
	}
}

// timer returns a timer configured for with the current backoff
// delay. Consumers can use this to wait for the appropriate period of time.
func (b *backoff) timer() *time.Timer {
	return time.NewTimer(b.next())
}

// expired returns true if the backoff timer has exceeded the timeout value.
func (b *backoff) expired() bool {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	return b.current >= b.timeout
}

// delay returns the current backoff duration without incrementing it.
func (b *backoff) delay() time.Duration {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	return b.current
}

// next returns the current backoff duration, and increments the internal
// backoff timer.
func (b *backoff) next() time.Duration {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	old := b.current
	b.current = b.current + b.current
	return old
}

// reset can be used to reset the internal backoff timer.
func (b *backoff) reset() {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.current = backoffStartDuration
}
