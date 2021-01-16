package rpccontext

import (
	"context"
)

type callerPIDKey struct{}

// WithCallerPID returns a context with the given caller PID
func WithCallerPID(ctx context.Context, pid int) context.Context {
	return context.WithValue(ctx, callerPIDKey{}, pid)
}

// CallerPID returns the caller pid.
func CallerPID(ctx context.Context) int {
	return ctx.Value(callerPIDKey{}).(int)
}
