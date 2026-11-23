//go:build !windows

package entrypoint

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEntryPoint(t *testing.T) {
	assert.Equal(t,
		0, NewEntryPoint(func(ctx context.Context, args []string) int { return 0 }).Main())

	assert.Equal(t,
		1, NewEntryPoint(func(ctx context.Context, args []string) int { return 1 }).Main())
}
