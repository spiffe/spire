package health_test

import (
	"context"
	"testing"

	"github.com/spiffe/spire/pkg/common/health"
	"github.com/stretchr/testify/assert"
)

func TestContext(t *testing.T) {
	assert.False(t, health.IsCheck(context.Background()))
	assert.True(t, health.IsCheck(health.CheckContext(context.Background())))
}
