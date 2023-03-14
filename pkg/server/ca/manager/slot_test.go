package manager

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/stretchr/testify/require"
)

func TestX509CASlotShouldPrepareNext(t *testing.T) {
	clock := clock.NewMock()
	now := clock.Now()

	slot := &X509CASlot{
		id:       "A",
		issuedAt: clock.Now(),
		x509CA:   nil,
	}

	// No x509CA should not prepare next
	require.False(t, slot.ShouldPrepareNext(now.Add(-time.Hour)))

	// Adding certificate with expiration
	slot.x509CA = &ca.X509CA{
		Certificate: &x509.Certificate{
			NotAfter: now.Add(time.Minute),
		},
	}

	// Just created no need to prepare
	require.False(t, slot.ShouldPrepareNext(now))

	// Advance to before preparation time
	require.False(t, slot.ShouldPrepareNext(now.Add(30*time.Second)))

	// Advance to preparation time
	require.True(t, slot.ShouldPrepareNext(now.Add(31*time.Second)))
}

func TestX509CASlotShouldActivateNext(t *testing.T) {
	clock := clock.NewMock()
	now := clock.Now()

	slot := &X509CASlot{
		id:       "A",
		issuedAt: now,
		x509CA:   nil,
	}

	// No x509CA should not prepare next
	require.False(t, slot.ShouldActivateNext(now.Add(-time.Hour)))

	// Adding certificate with expiration
	slot.x509CA = &ca.X509CA{
		Certificate: &x509.Certificate{
			NotAfter: now.Add(time.Minute),
		},
	}

	// Just created no need to activate
	require.False(t, slot.ShouldActivateNext(now))

	// Advance to before preparation time
	require.False(t, slot.ShouldActivateNext(now.Add(50*time.Second)))

	// Advance to preparation time
	require.True(t, slot.ShouldActivateNext(now.Add(51*time.Second)))
}

func TestJWTKeySlotShouldPrepareNext(t *testing.T) {
	clock := clock.NewMock()
	now := clock.Now()

	slot := &JwtKeySlot{
		id:       "A",
		issuedAt: now,
		jwtKey:   nil,
	}

	// No jwt key, should prepare
	require.True(t, slot.ShouldPrepareNext(now.Add(time.Hour)))

	// Key is not ready to prepare
	slot.jwtKey = &ca.JWTKey{
		NotAfter: now.Add(time.Minute),
	}
	// Just created no need to prepare
	require.False(t, slot.ShouldPrepareNext(now))

	// Advance to before preparation time
	require.False(t, slot.ShouldPrepareNext(now.Add(30*time.Second)))

	// Advance to preparation time
	require.True(t, slot.ShouldPrepareNext(now.Add(31*time.Second)))
}

func TestJWTKeySlotShouldActivateNext(t *testing.T) {
	now := time.Now()

	slot := &JwtKeySlot{
		id:       "A",
		issuedAt: now,
		jwtKey:   nil,
	}

	// No jwt key, should activate
	require.True(t, slot.ShouldActivateNext(now.Add(time.Hour)))

	// Key is not ready to prepare
	slot.jwtKey = &ca.JWTKey{
		NotAfter: now.Add(time.Minute),
	}
	// Just created no need to prepare
	require.False(t, slot.ShouldActivateNext(now))

	// Advance to before activation time
	require.False(t, slot.ShouldActivateNext(now.Add(50*time.Second)))

	// Advance to preparation time
	require.True(t, slot.ShouldActivateNext(now.Add(51*time.Second)))
}
