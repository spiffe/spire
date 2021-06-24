package health

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContext(t *testing.T) {
	assert.False(t, IsHealthCheck(context.Background()))
	assert.True(t, IsHealthCheck(AsHealthCheck(context.Background())))
}
