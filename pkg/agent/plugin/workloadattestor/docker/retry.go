package docker

import (
	"context"
	"math"
	"time"

	"github.com/andres-erbsen/clock"
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

func (r *retryer) Retry(ctx context.Context, fn func() error) error {
	if r.disabled {
		return fn()
	}
	// try once plus the number of retries
	for i := 0; ; i++ {
		err := fn()
		if err == nil {
			return nil
		}
		// don't wait another backoff cycle if we've already maxed out on retries
		if i == r.numRetries {
			return err
		}
		backoff := r.initialBackoff * time.Duration(exponentialBackoff(i))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.clock.After(backoff):
		}
	}
}

func exponentialBackoff(c int) float64 {
	return math.Pow(2, float64(c))
}
