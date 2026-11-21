package nodeattestor

import (
	"context"
	"time"
)

func WithTimeout(inner NodeAttestor, timeout time.Duration) NodeAttestor {
	if timeout <= 0 {
		return inner
	}
	return &attestorWithTimeout{NodeAttestor: inner, timeout: timeout}
}

type attestorWithTimeout struct {
	NodeAttestor
	timeout time.Duration
}

func (t *attestorWithTimeout) Attest(ctx context.Context, serverStream ServerStream) error {
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	return t.NodeAttestor.Attest(ctx, serverStream)
}
