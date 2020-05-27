package rpccontext

import (
	"context"

	"github.com/spiffe/spire/pkg/server/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type rateLimiterKey struct{}

func WithRateLimiter(ctx context.Context, limiter api.RateLimiter) context.Context {
	return context.WithValue(ctx, rateLimiterKey{}, limiter)
}

func RateLimiter(ctx context.Context) (api.RateLimiter, bool) {
	value, ok := ctx.Value(rateLimiterKey{}).(api.RateLimiter)
	return value, ok
}

func RateLimit(ctx context.Context, count int) error {
	limiter, ok := RateLimiter(ctx)
	if !ok {
		return status.Errorf(codes.Internal, "rate limiter unavailable")
	}
	return limiter.RateLimit(ctx, count)
}
