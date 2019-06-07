package docker

import (
	"context"
	"math"
	"time"

	"github.com/spiffe/spire/test/clock"
)

const (
	defaultNumRetries     = 3
	defaultInitialBackoff = 100 * time.Millisecond
)

var disabledRetryer = &retryer{disabled: true}

type retryer struct {
	clock          clock.Clock
	disabled       bool
	numRetries     int
	initialBackoff time.Duration
}

func newRetryer() *retryer {
	return &retryer{
		clock:          clock.New(),
		numRetries:     defaultNumRetries,
		initialBackoff: defaultInitialBackoff,
	}
}

func (r *retryer) Retry(ctx context.Context, fn func() error) {
	if r.disabled {
		fn()
		return
	}
	// try once plus the number of retries
	for i := 0; i <= r.numRetries; i++ {
		if err := fn(); err == nil {
			return
		}
		// don't wait another backoff cycle if we've already maxed out on retries
		if i == r.numRetries {
			return
		}
		backoff := r.initialBackoff * time.Duration(exponentialBackoff(i))
		select {
		case <-ctx.Done():
			return
		case <-r.clock.After(backoff):
		}
	}
}

func exponentialBackoff(c int) float64 {
	return math.Pow(2, float64(c))
}
