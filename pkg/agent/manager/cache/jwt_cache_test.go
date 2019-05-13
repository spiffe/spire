package cache

import (
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/stretchr/testify/assert"
)

func TestJWTSVIDCache(t *testing.T) {
	now := time.Now()
	expected := &client.JWTSVID{Token: "X", IssuedAt: now, ExpiresAt: now.Add(time.Second)}

	cache := NewJWTSVIDCache()

	// JWT is not cached
	actual, ok := cache.GetJWTSVID("spiffe://example.org/blog", []string{"bar"})
	assert.False(t, ok)
	assert.Nil(t, actual)

	// JWT is cached
	cache.SetJWTSVID("spiffe://example.org/blog", []string{"bar"}, expected)
	actual, ok = cache.GetJWTSVID("spiffe://example.org/blog", []string{"bar"})
	assert.True(t, ok)
	assert.Equal(t, expected, actual)
}
