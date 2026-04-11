package middleware

import (
	"context"
	"errors"
	"net"

	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/ratelimit"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// newRawRateLimiter is used to create a new ratelimiter. It returns a limiter
	// from the standard rate package by default production.
	newRawRateLimiter = func(limit rate.Limit, burst int) ratelimit.Limiter {
		return rate.NewLimiter(limit, burst)
	}
)

// perKeyLimiterOpts holds options for creating per-key limiters.
// Exposed for testing (e.g., clock injection).
var perKeyLimiterOpts []ratelimit.Option

type noopRateLimiter interface {
	noop()
}

// NoLimit returns a rate limiter that does not rate limit. It is used to
// configure methods that don't do rate limiting.
func NoLimit() api.RateLimiter {
	return noLimit{}
}

// DisabledLimit returns a rate limiter that does not rate limit. It is used to
// configure methods where rate limiting has been disabled by configuration.
func DisabledLimit() api.RateLimiter {
	return disabledLimit{}
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
// group of methods described by the rateLimits map. It provides the
// configured rate limiter to the method handlers via the request context. If
// the middleware is invoked for a method that is not described in the map, it
// will fail the RPC with an INTERNAL error code, describing the RPC that was
// not configured properly. The middleware also encourages proper rate limiting
// by logging errors if a handler fails to invoke the rate limiter provided on
// the context when a limit has been configured or the handler invokes the rate
// limiter when a no limit has been configured.
//
// WithRateLimits owns the passed rateLimits map and assumes it will not be
// mutated after the method is called.
//
// The WithRateLimits middleware depends on the Logger and Authorization
// middlewares.
func WithRateLimits(rateLimits map[string]api.RateLimiter, metrics telemetry.Metrics) middleware.Middleware {
	return rateLimitsMiddleware{
		limiters: rateLimits,
		metrics:  metrics,
	}
}

type noLimit struct{}

func (noLimit) RateLimit(context.Context, int) error {
	return nil
}

func (noLimit) noop() {}

type disabledLimit struct{}

func (disabledLimit) RateLimit(context.Context, int) error {
	return nil
}

func (disabledLimit) noop() {}

type perCallLimiter struct {
	limiter ratelimit.Limiter
}

func newPerCallLimiter(limit int) *perCallLimiter {
	return &perCallLimiter{limiter: newRawRateLimiter(rate.Limit(limit), limit)}
}

func (lim *perCallLimiter) RateLimit(ctx context.Context, count int) error {
	return waitN(ctx, lim.limiter, count)
}

type perIPLimiter struct {
	inner *ratelimit.PerKeyLimiter
}

func newPerIPLimiter(limit int) *perIPLimiter {
	return &perIPLimiter{
		inner: ratelimit.NewPerKeyLimiter(func() ratelimit.Limiter {
			return newRawRateLimiter(rate.Limit(limit), limit)
		}, perKeyLimiterOpts...),
	}
}

func (lim *perIPLimiter) RateLimit(ctx context.Context, count int) error {
	tcpAddr, ok := rpccontext.CallerAddr(ctx).(*net.TCPAddr)
	if !ok {
		// Calls not via TCP/IP aren't limited
		return nil
	}
	limiter := lim.inner.GetLimiter(tcpAddr.IP.String())
	return waitN(ctx, limiter, count)
}

type rateLimitsMiddleware struct {
	limiters map[string]api.RateLimiter
	metrics  telemetry.Metrics
}

func (i rateLimitsMiddleware) Preprocess(ctx context.Context, fullMethod string, _ any) (context.Context, error) {
	rateLimiter, ok := i.limiters[fullMethod]
	if !ok {
		middleware.LogMisconfiguration(ctx, "Rate limiting misconfigured; this is a bug")
		return nil, status.Errorf(codes.Internal, "rate limiting misconfigured for %q", fullMethod)
	}
	return rpccontext.WithRateLimiter(ctx, &rateLimiterWrapper{rateLimiter: rateLimiter, metrics: i.metrics}), nil
}

func (i rateLimitsMiddleware) Postprocess(ctx context.Context, _ string, handlerInvoked bool, rpcErr error) {
	// Handlers are expected to invoke the rate limiter unless they failed to
	// parse parameters. If the handler itself wasn't invoked then there is no
	// need to check if rate limiting was invoked.
	if !handlerInvoked || status.Code(rpcErr) == codes.InvalidArgument {
		return
	}

	rateLimiter, ok := rpccontext.RateLimiter(ctx)
	if !ok {
		// This shouldn't be the case unless Preprocess is broken and fails to
		// inject the rate limiter into the context.
		middleware.LogMisconfiguration(ctx, "Rate limiting misconfigured; this is a bug")
		return
	}

	wrapper, ok := rateLimiter.(*rateLimiterWrapper)
	if !ok {
		// This shouldn't be the case unless Preprocess is broken and fails to
		// wrap the rate limiter.
		middleware.LogMisconfiguration(ctx, "Rate limiting misconfigured; this is a bug")
		return
	}

	logLimiterMisuse(ctx, wrapper.rateLimiter, wrapper.Used())
}

func logLimiterMisuse(ctx context.Context, rateLimiter api.RateLimiter, used bool) {
	switch rateLimiter.(type) {
	case noLimit:
		// RPC should not invoke the rate limiter, since that would imply a
		// misconfiguration. Either the RPC is wrong, or the middleware is
		// wrong as to whether the RPC should rate limit.
		if used {
			middleware.LogMisconfiguration(ctx, "Rate limiter used unexpectedly; this is a bug")
		}
	case disabledLimit:
		// RPC should invoke the rate limiter since is an RPC that is normally
		// rate limited. The disabled limiter will not actually apply any
		// limits but we want to make sure the RPC will be applying limits
		// under normal conditions.
		if !used {
			middleware.LogMisconfiguration(ctx, "Disabled rate limiter went unused; this is a bug")
		}
	default:
		// All other rate limiters should definitely be invoked by the RPC or
		// it is a bug.
		if !used {
			middleware.LogMisconfiguration(ctx, "Rate limiter went unused; this is a bug")
		}
	}
}

type rateLimiterWrapper struct {
	rateLimiter api.RateLimiter
	used        bool
	metrics     telemetry.Metrics
}

func (w *rateLimiterWrapper) RateLimit(ctx context.Context, count int) (err error) {
	w.used = true
	if _, noop := w.rateLimiter.(noopRateLimiter); !noop {
		counter := telemetry.StartCall(w.metrics, "rateLimit", getNames(ctx)...)
		defer counter.Done(&err)
	}

	return w.rateLimiter.RateLimit(ctx, count)
}

func (w *rateLimiterWrapper) Used() bool {
	return w.used
}

func getNames(ctx context.Context) []string {
	names, ok := rpccontext.Names(ctx)
	if ok {
		return names.MetricKey
	}
	return []string{}
}

func waitN(ctx context.Context, limiter ratelimit.Limiter, count int) (err error) {
	// limiter.WaitN already provides this check but the error returned is not
	// strongly typed and is a little messy. Lifting this check so we can
	// provide a clean error message.
	if count > limiter.Burst() && limiter.Limit() != rate.Inf {
		return status.Errorf(codes.ResourceExhausted, "rate (%d) exceeds burst size (%d)", count, limiter.Burst())
	}

	err = limiter.WaitN(ctx, count)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return ctx.Err()
	default:
		return status.Error(codes.ResourceExhausted, err.Error())
	}
}
