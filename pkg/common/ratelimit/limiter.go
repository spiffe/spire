package ratelimit

import (
	"context"
	"time"

	"golang.org/x/time/rate"
)

// Limiter covers both blocking (WaitN) and non-blocking (AllowN) rate limiting.
// *rate.Limiter satisfies this interface.
type Limiter interface {
	AllowN(now time.Time, n int) bool
	WaitN(ctx context.Context, n int) error
	Limit() rate.Limit
	Burst() int
}
