package rotationutil

import (
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShouldRotateX509(t *testing.T) {
	// Cert that's valid for 1hr
	mockClk := clock.NewMock(t)
	temp, err := util.NewSVIDTemplate(mockClk, "spiffe://example.org/test")
	require.NoError(t, err)
	goodCert, _, err := util.SelfSign(temp)
	require.NoError(t, err)

	// Cert is brand new
	assert.False(t, ShouldRotateX509(mockClk.Now(), goodCert))

	// Cert that's almost expired
	temp.NotBefore = mockClk.Now().Add(-1 * time.Hour)
	temp.NotAfter = mockClk.Now().Add(1 * time.Minute)
	badCert, _, err := util.SelfSign(temp)
	require.NoError(t, err)

	assert.True(t, ShouldRotateX509(mockClk.Now(), badCert))
}

func TestJWTSVIDExpiresSoon(t *testing.T) {
	// JWT that's valid for 1hr
	mockClk := clock.NewMock(t)
	goodJWT := &client.JWTSVID{
		IssuedAt:  mockClk.Now(),
		ExpiresAt: mockClk.Now().Add(time.Hour),
	}

	// JWT is brand new
	assert.False(t, JWTSVIDExpiresSoon(goodJWT, mockClk.Now()))

	// JWT that's almost expired
	badJWT := &client.JWTSVID{
		IssuedAt:  mockClk.Now().Add(-1 * time.Hour),
		ExpiresAt: mockClk.Now().Add(1 * time.Minute),
	}

	assert.True(t, JWTSVIDExpiresSoon(badJWT, mockClk.Now()))

	// JWT that is expired
	expiredJWT := &client.JWTSVID{
		IssuedAt:  mockClk.Now().Add(-1 * time.Hour),
		ExpiresAt: mockClk.Now().Add(-30 * time.Minute),
	}

	assert.True(t, JWTSVIDExpiresSoon(expiredJWT, mockClk.Now()))
}
