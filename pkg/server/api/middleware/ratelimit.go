package middleware

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// NewRateLimiter is used to create a new ratelimiter. It returns a limiter
	// from the standard rate package by default production.
	newRawRateLimiter = func(limit rate.Limit, burst int) rawRateLimiter {
		return rate.NewLimiter(limit, burst)
	}
)

// rawRateLimiter represents the raw limiter functionality.
type rawRateLimiter interface {
	WaitN(ctx context.Context, count int) error
	Limit() rate.Limit
	Burst() int
}

// NoLimit returns a rate limiter does not rate limit. It is used to configure
// methods that don't do rate limiting.
func NoLimit() api.RateLimiter {
	return noopLimiter{}
}

// PerCallLimit returns a rate limiter that imposes a server-wide limit for
// calls to the method. It can be shared across methods to enforce a
// server-wide limit for a group of methods.
func PerCallLimit(limit int) api.RateLimiter {
	return newPerCallLimiter(limit)
}

// PerIPLimit returns a rate limiter that imposes a per-ip limit on calls
// to a method. It can be shared across methods to enforce per-ip limits for
// a group of methods.
func PerIPLimit(limit int) api.RateLimiter {
	return newPerIPLimiter(limit)
}

// WithRateLimits returns a middleware that performs rate limiting for the
// group of methods descripted by the rateLimits map. It provides the
// configured rate limiter to the method handlers via the request context. If
// the middleware is invoked for a method is not described in the map, it will
// fail the RPC with an INTERNAL error code, describing the RPC that was not
// configured properly.  The middleware also encourages proper rate limiting by
// logging errors if a handler fails to invoke the rate limiter provided on the
// context when a limit has been configured or the handler invokes the rate
// limiter when a no limit has been configured.
//
// The WithRateLimits middleware depends on the Logger and Authorization
// middlewares.
func WithRateLimits(rateLimits map[string]api.RateLimiter) Middleware {
	return rateLimitsMiddleware{
		limiters: rateLimits,
	}
}

type noopLimiter struct{}

func (noopLimiter) RateLimit(ctx context.Context, count int) error {
	return nil
}

func (noopLimiter) Noop() bool { return true }

func isNoopLimiter(rateLimiter api.RateLimiter) bool {
	noop, ok := rateLimiter.(interface{ Noop() bool })
	return ok && noop.Noop()
}

type perCallLimiter struct {
	limiter rawRateLimiter
}

func newPerCallLimiter(limit int) *perCallLimiter {
	return &perCallLimiter{limiter: newRawRateLimiter(rate.Limit(limit), limit)}
}

func (lim *perCallLimiter) RateLimit(ctx context.Context, count int) error {
	return waitN(ctx, lim.limiter, count)
}

type perIPLimiter struct {
	limit int

	mtx      sync.RWMutex
	limiters map[string]rawRateLimiter
}

func newPerIPLimiter(limit int) *perIPLimiter {
	return &perIPLimiter{limit: limit,
		limiters: make(map[string]rawRateLimiter),
	}
}

func (lim *perIPLimiter) RateLimit(ctx context.Context, count int) error {
	tcpAddr, ok := rpccontext.CallerAddr(ctx).(*net.TCPAddr)
	if !ok {
		// Calls not via TCP/IP aren't limited
		return nil
	}
	limiter := lim.getLimiter(tcpAddr.IP.String())
	return waitN(ctx, limiter, count)
}

func (lim *perIPLimiter) getLimiter(addr string) rawRateLimiter {
	lim.mtx.RLock()
	limiter, ok := lim.limiters[addr]
	if ok {
		lim.mtx.RUnlock()
		return limiter
	}
	lim.mtx.RUnlock()

	lim.mtx.Lock()
	defer lim.mtx.Unlock()
	limiter, ok = lim.limiters[addr]
	if !ok {
		limiter = newRawRateLimiter(rate.Limit(lim.limit), lim.limit)
		lim.limiters[addr] = limiter
	}

	return limiter
}

type rateLimitsMiddleware struct {
	limiters map[string]api.RateLimiter
}

func (i rateLimitsMiddleware) Preprocess(ctx context.Context, methodName string) (context.Context, error) {
	rateLimiter, ok := i.limiters[methodName]
	if !ok {
		rpccontext.Logger(ctx).WithField("method", methodName).Error("Rate limiting misconfigured; this is a bug")
		return nil, status.Errorf(codes.Internal, "rate limiting misconfigured for RPC %q", methodName)
	}
	return rpccontext.WithRateLimiter(ctx, &rateLimiterWrapper{rateLimiter: rateLimiter}), nil
}

func (i rateLimitsMiddleware) Postprocess(ctx context.Context, methodName string, handlerInvoked bool, rpcErr error) {
	// Handlers are expected to invoke the rate limiter unless they failed to
	// parse parameters.
	if handlerInvoked && status.Code(rpcErr) == codes.InvalidArgument {
		return
	}

	rateLimiter, ok := rpccontext.RateLimiter(ctx)
	if !ok {
		// This shouldn't be the case unless Preprocess is broken and fails to
		// inject the rate limiter into the context.
		rpccontext.Logger(ctx).WithField("method", methodName).Error("Rate limiting misconfigured; this is a bug")
		return
	}

	wrapper, ok := rateLimiter.(*rateLimiterWrapper)
	if !ok {
		// This shouldn't be the case unless Preprocess is broken and fails
		// to wrap the rate limiter.
		rpccontext.Logger(ctx).WithField("method", methodName).Error("Rate limiting misconfigured; this is a bug")
		return
	}

	noop := isNoopLimiter(wrapper.rateLimiter)
	used := wrapper.Used()

	switch {
	case !noop && !used:
		// The limiter was non-noop and went unused by the handler. This is a bug.
		rpccontext.Logger(ctx).WithField("method", methodName).Error("Rate limiter went unused; this is a bug")
	case !noop && used:
		// The limiter was non-noop and was used. All is well.
	case noop && !used:
		// The limiter was noop and was not used. All is well.
	case noop && used:
		// The limiter was noop and was used. This is a bug.
		rpccontext.Logger(ctx).WithField("method", methodName).Error("Rate limiter used unexpectedly; this is a bug")
	}
}

type rateLimiterWrapper struct {
	rateLimiter api.RateLimiter
	used        bool
}

func (w *rateLimiterWrapper) RateLimit(ctx context.Context, count int) error {
	w.used = true
	return w.rateLimiter.RateLimit(ctx, count)
}

func (w *rateLimiterWrapper) Used() bool {
	return w.used
}

func waitN(ctx context.Context, limiter rawRateLimiter, count int) error {
	// limiter.WaitN already provides this check but the error returned is not
	// strongly typed and is a little messy. Lifting this check so we can
	// provide a clean error message.
	if count > limiter.Burst() && limiter.Limit() != rate.Inf {
		return status.Errorf(codes.ResourceExhausted, "rate (%d) exceeds burst size (%d)", count, limiter.Burst())
	}

	err := limiter.WaitN(ctx, count)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return ctx.Err()
	default:
		return status.Error(codes.ResourceExhausted, err.Error())
	}
}
