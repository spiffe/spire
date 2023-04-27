package rotationutil

import (
	"crypto/x509"
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

	// Cert that's almost expired
	temp.NotBefore = mockClk.Now().Add(-1 * time.Hour)
	temp.NotAfter = mockClk.Now().Add(1 * time.Minute)
	almostExpiredCert, _, err := util.SelfSign(temp)
	require.NoError(t, err)

	for _, tc := range []struct {
		desc         string
		cert         *x509.Certificate
		rotateBefore time.Duration
		expectResult bool
	}{
		{
			desc:         "cert lifetime=1h and rotate through 1/2 of lifetime",
			cert:         goodCert,
			expectResult: false,
		},
		{
			desc:         "cert lifetime=1m and rotate through 1/2 of lifetime",
			cert:         almostExpiredCert,
			expectResult: true,
		},
		{
			desc:         "cert lifetime=1h and rotate before 1h",
			cert:         goodCert,
			rotateBefore: 1 * time.Hour,
			expectResult: true,
		},
		{
			desc:         "cert lifetime=1h and rotate before 30m",
			cert:         goodCert,
			rotateBefore: 30 * time.Minute,
			expectResult: false,
		},
		{
			desc:         "cert lifetime=1m and rotate before 1m",
			cert:         almostExpiredCert,
			rotateBefore: 1 * time.Minute,
			expectResult: true,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			actual := ShouldRotateX509(mockClk.Now(), tc.cert, tc.rotateBefore)
			assert.Equal(t, tc.expectResult, actual)
		})
	}
}

func TestX509Expired(t *testing.T) {
	// Cert that's valid for 1hr
	mockClk := clock.NewMock(t)
	temp, err := util.NewSVIDTemplate(mockClk, "spiffe://example.org/test")
	require.NoError(t, err)
	goodCert, _, err := util.SelfSign(temp)
	require.NoError(t, err)

	// Cert is brand new
	assert.False(t, X509Expired(mockClk.Now(), goodCert))

	// Cert that's almost expired
	temp.NotBefore = mockClk.Now().Add(-1 * time.Hour)
	temp.NotAfter = mockClk.Now()
	stillGoodCert, _, err := util.SelfSign(temp)
	require.NoError(t, err)

	assert.False(t, X509Expired(mockClk.Now(), stillGoodCert))

	// Cert that's just expired
	temp.NotBefore = mockClk.Now().Add(-1 * time.Hour)
	temp.NotAfter = mockClk.Now().Add(-1 * time.Nanosecond)
	justBadCert, _, err := util.SelfSign(temp)
	require.NoError(t, err)

	assert.True(t, X509Expired(mockClk.Now(), justBadCert))
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
