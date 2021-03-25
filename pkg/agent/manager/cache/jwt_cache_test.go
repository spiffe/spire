package cache

import (
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/stretchr/testify/assert"
)

func TestJWTSVIDCache(t *testing.T) {
	now := time.Now()
	expected := &client.JWTSVID{Token: "X", IssuedAt: now, ExpiresAt: now.Add(time.Second)}

	cache := NewJWTSVIDCache()

	spiffeID := spiffeid.RequireFromString("spiffe://example.org/blog")

	// JWT is not cached
	actual, ok := cache.GetJWTSVID(spiffeID, []string{"bar"})
	assert.False(t, ok)
	assert.Nil(t, actual)

	// JWT is cached
	cache.SetJWTSVID(spiffeID, []string{"bar"}, expected)
	actual, ok = cache.GetJWTSVID(spiffeID, []string{"bar"})
	assert.True(t, ok)
	assert.Equal(t, expected, actual)
}
