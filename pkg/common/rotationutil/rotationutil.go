package rotationutil

import (
	"crypto/x509"
	"math/rand"
	"time"

	"github.com/spiffe/spire/pkg/agent/client"
)

// ShouldRotateX509 determines if a given SVID should be rotated, based
// on presented current time, and the certificate's expiration.
func ShouldRotateX509(now time.Time, cert *x509.Certificate) bool {
	return shouldRotate(now, cert.NotBefore, cert.NotAfter)
}

// X509Expired returns true if the given X509 cert has expired
func X509Expired(now time.Time, cert *x509.Certificate) bool {
	return now.After(cert.NotAfter)
}

// JWTSVIDExpiresSoon determines if the given JWT SVID should be rotated
// based on presented current time, the JWT's expiration.
// Also returns true if the JWT is already expired.
func JWTSVIDExpiresSoon(svid *client.JWTSVID, now time.Time) bool {
	if JWTSVIDExpired(svid, now) {
		return true
	}

	// if the SVID has less than half of its lifetime left, consider it
	// as expiring soon
	return shouldRotate(now, svid.IssuedAt, svid.ExpiresAt)
}

// JWTSVIDExpired returns true if the given SVID is expired.
func JWTSVIDExpired(svid *client.JWTSVID, now time.Time) bool {
	return !now.Before(svid.ExpiresAt)
}

func shouldRotate(now, beginTime, expiryTime time.Time) bool {
	ttl := expiryTime.Sub(now)
	// return true quickly if the expiry is already met.
	if ttl <= 0 {
		return true
	}

	halfLife := halfLife(beginTime, expiryTime)

	// calculate a jitter delta to spread out rotations
	delta := jitterDelta(halfLife)
	min := halfLife - delta

	jitteredHalfLife := time.Duration(rand.Int63n(int64(delta)*2) + int64(min)) //nolint // gosec: no need for cryptographic randomness here

	return ttl <= jitteredHalfLife
}

// jitterDelta is a calculated delta centered to the half-life of the SVID.
// It's to spread out the renewal of SVID rotations to avoid spiky renewal requests.
// The jitter is calculated as ± 10% of the half-life of the SVID.
func jitterDelta(halfLife time.Duration) time.Duration {
	// ± 10% of the half-life
	return halfLife / 10
}

func halfLife(beginTime, expiryTime time.Time) time.Duration {
	lifetime := expiryTime.Sub(beginTime)
	return lifetime / 2
}
