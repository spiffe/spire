package api

import "context"

type RateLimiter interface {
	RateLimit(ctx context.Context, count int) error
}

type RateLimiterFunc func(ctx context.Context, count int) error

func (fn RateLimiterFunc) RateLimit(ctx context.Context, count int) error {
	return fn(ctx, count)
}
