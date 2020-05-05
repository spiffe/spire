package rpccontext

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type rateLimiterKey struct{}

type RateLimiter struct {
	Used bool
}

func WithRateLimiter(ctx context.Context, limiter *RateLimiter) context.Context {
	return context.WithValue(ctx, rateLimiterKey{}, limiter)
}

func RateLimit(ctx context.Context, count int) error {
	limiter, ok := ctx.Value(rateLimiterKey{}).(*RateLimiter)
	if !ok {
		return status.Errorf(codes.ResourceExhausted, "rate limiting not configured")
	}
	limiter.Used = true
	// TODO: actually to rate limiting
	return nil
}
