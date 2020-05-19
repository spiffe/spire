package middleware

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNoLimit(t *testing.T) {
	limiters := NewFakeLimiters()

	// NoLimit() does not do rate limiting and should succeed.
	m := NoLimit()
	require.NoError(t, m.RateLimit(context.Background(), 99))

	// There should be no rate limiters configured as NoLimit() doesn't use one.
	assert.Equal(t, 0, limiters.Count)
}

func TestPerCallLimit(t *testing.T) {
	limiters := NewFakeLimiters()

	m := PerCallLimit(1)

	// Exceeds burst size.
	err := m.RateLimit(context.Background(), 2)
	spiretest.RequireGRPCStatus(t, err, codes.ResourceExhausted, "rate (2) exceeds burst size (1)")

	// Within burst size.
	require.NoError(t, m.RateLimit(context.Background(), 1))

	// There should be a single rate limiter. WaitN should have only been
	// called once for the call that didn't exceed the burst size.
	assert.Equal(t, 1, limiters.Count)
	assert.Equal(t, []WaitNEvent{
		{ID: 1, Count: 1},
	}, limiters.WaitNEvents)
}

func TestPerIPLimit(t *testing.T) {
	limiters := NewFakeLimiters()

	m := PerIPLimit(10)

	// Does not rate limit non-TCP/IP callers
	err := m.RateLimit(context.Background(), 11)
	require.NoError(t, err)

	// Once exceeding burst size for 1.1.1.1
	err = m.RateLimit(callerIPCtx("1.1.1.1"), 11)
	spiretest.RequireGRPCStatus(t, err, codes.ResourceExhausted, "rate (11) exceeds burst size (10)")

	// Once within burst size for 1.1.1.1
	require.NoError(t, m.RateLimit(callerIPCtx("1.1.1.1"), 1))

	// Twice within burst size for 2.2.2.2
	require.NoError(t, m.RateLimit(callerIPCtx("2.2.2.2"), 2))
	require.NoError(t, m.RateLimit(callerIPCtx("2.2.2.2"), 3))

	// There should be two rate limiters; 1.1.1.1, and 2.2.2.2
	assert.Equal(t, 2, limiters.Count)

	// WaitN should have only been called once for 1.1.1.1 (burst failure does
	// not result in a call to WaitN) and twice for 2.2.2.2.
	assert.Equal(t, []WaitNEvent{
		{ID: 1, Count: 1},
		{ID: 2, Count: 2},
		{ID: 2, Count: 3},
	}, limiters.WaitNEvents)
}

func TestRateLimits(t *testing.T) {
	unaryInterceptor := UnaryInterceptor(
		WithRateLimits(
			map[string]api.RateLimiter{
				"/fake.Service/NoLimit":   NoLimit(),
				"/fake.Service/WithLimit": PerCallLimit(2),
			},
		),
	)

	for _, tt := range []struct {
		name           string
		method         string
		prepareCtx     func(context.Context) context.Context
		rateLimitCount int
		returnErr      error
		expectLogs     []spiretest.LogEntry
		expectCode     codes.Code
		expectMsg      string
	}{
		{
			name:       "RPC fails if method not configured for rate limiting",
			method:     "/fake.Service/Whoopsie",
			expectCode: codes.Internal,
			expectMsg:  `rate limiting misconfigured for RPC "/fake.Service/Whoopsie"`,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Rate limiting misconfigured; this is a bug",
					Data: logrus.Fields{
						"method": "/fake.Service/Whoopsie",
					},
				},
			},
		},
		{
			name:       "logs when rate limiter not used by handler",
			method:     "/fake.Service/WithLimit",
			expectCode: codes.OK,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Rate limiter went unused; this is a bug",
					Data: logrus.Fields{
						"method": "/fake.Service/WithLimit",
					},
				},
			},
		},
		{
			name:       "does not log if handler returns",
			method:     "/fake.Service/WithLimit",
			returnErr:  status.Error(codes.InvalidArgument, "ohno!"),
			expectCode: codes.InvalidArgument,
			expectMsg:  `ohno!`,
		},
		{
			name:           "logs when handler with no limit tries to rate limit",
			method:         "/fake.Service/NoLimit",
			rateLimitCount: 1,
			expectCode:     codes.OK,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Rate limiter used unexpectedly; this is a bug",
					Data: logrus.Fields{
						"method": "/fake.Service/NoLimit",
					},
				},
			},
		},
		{
			name:       "does not when rate limiter not used by unlimited handler",
			method:     "/fake.Service/NoLimit",
			expectCode: codes.OK,
		},
		{
			name:           "does not log when rate limiter used by limited handler",
			method:         "/fake.Service/WithLimit",
			rateLimitCount: 1,
		},
		{
			name:           "returns resource exhausted when rate limiting fails",
			method:         "/fake.Service/WithLimit",
			rateLimitCount: 3,
			expectCode:     codes.ResourceExhausted,
			expectMsg:      "rate (3) exceeds burst size (2)",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			log, hook := test.NewNullLogger()
			ctx := rpccontext.WithLogger(context.Background(), log)
			if tt.prepareCtx != nil {
				ctx = tt.prepareCtx(ctx)
			}
			serverInfo := &grpc.UnaryServerInfo{FullMethod: tt.method}

			handler := func(ctx context.Context, _ interface{}) (interface{}, error) {
				if tt.rateLimitCount > 0 {
					if err := rpccontext.RateLimit(ctx, tt.rateLimitCount); err != nil {
						return nil, err
					}
				}
				if tt.returnErr != nil {
					return nil, tt.returnErr
				}
				return struct{}{}, nil
			}

			resp, err := unaryInterceptor(ctx, struct{}{}, serverInfo, handler)
			spiretest.AssertGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			if err == nil {
				assert.NotNil(t, resp)
			} else {
				assert.Nil(t, resp)
			}
			spiretest.AssertLogs(t, hook.AllEntries(), tt.expectLogs)
		})
	}
}

type WaitNEvent struct {
	ID    int
	Count int
}

type FakeLimiters struct {
	Count       int
	WaitNEvents []WaitNEvent
}

func NewFakeLimiters() *FakeLimiters {
	ls := &FakeLimiters{}
	newRawRateLimiter = ls.newRawRateLimiter
	return ls
}

func (ls *FakeLimiters) newRawRateLimiter(limit rate.Limit, burst int) rawRateLimiter {
	ls.Count++
	return &fakeLimiter{
		id:    ls.Count,
		waitN: ls.waitN,
		limit: limit,
		burst: burst,
	}
}

func (ls *FakeLimiters) waitN(ctx context.Context, id, count int) error {
	ls.WaitNEvents = append(ls.WaitNEvents, WaitNEvent{
		ID:    id,
		Count: count,
	})
	return nil
}

type fakeLimiter struct {
	id    int
	waitN func(ctx context.Context, id, count int) error
	limit rate.Limit
	burst int
}

func (l *fakeLimiter) WaitN(ctx context.Context, count int) error {
	switch {
	case l.limit == rate.Inf:
		// Limiters should never be unlimited.
		return errors.New("unexpected infinite limit on limiter")
	case count > l.burst:
		// the waitN() function should have already taken care of this check
		// in order to provide nicer error messaging than that provided by
		// the rate package.
		return errors.New("exceeding burst should have already been handled")
	}
	return l.waitN(ctx, l.id, count)
}

func (l *fakeLimiter) Limit() rate.Limit {
	return l.limit
}

func (l *fakeLimiter) Burst() int {
	return l.burst
}

func callerIPCtx(ip string) context.Context {
	return rpccontext.WithCallerAddr(context.Background(), &net.TCPAddr{
		IP: net.ParseIP(ip),
	})
}
