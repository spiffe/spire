//go:build !windows

package entrypoint

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEntryPoint(t *testing.T) {
	assert.Equal(t,
		NewEntryPoint(func(ctx context.Context, args []string) int { return 0 }).Main(),
		0)

	assert.Equal(t,
		NewEntryPoint(func(ctx context.Context, args []string) int { return 1 }).Main(),
		1)
}
