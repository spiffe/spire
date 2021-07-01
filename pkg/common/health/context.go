package health

import "context"

type healthCheckKey struct{}

func IsCheck(ctx context.Context) bool {
	_, ok := ctx.Value(healthCheckKey{}).(struct{})
	return ok
}

func CheckContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, healthCheckKey{}, struct{}{})
}
