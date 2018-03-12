package workload

import (
	"time"
)

type backoff struct {
	current time.Duration
	timeout time.Duration

	failOnError bool
}

func newBackoff(timeout time.Duration, failOnError bool) *backoff {
	return &backoff{
		current:     1 * time.Second,
		timeout:     timeout,
		failOnError: failOnError,
	}
}

func (b *backoff) goAgain(shutdown <-chan struct{}) bool {
	if b.failOnError {
		return false
	}

	if b.current > b.timeout {
		return false
	}

	select {
	case <-time.NewTicker(b.current).C:
		b.current = b.current + b.current
		return true
	case <-shutdown:
		return false
	}
}
