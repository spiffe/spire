package rotationutil

import (
	"crypto/x509"
	"math/rand"
	"time"

	"github.com/spiffe/spire/pkg/agent/client"
)

const (
	gracePeriodThreshold = 12 * time.Hour
)

type RotationStrategy struct {
	x509AvailabilityTarget time.Duration
}

func NewRotationStrategy(x509AvailabilityTarget time.Duration) *RotationStrategy {
	return &RotationStrategy{
		x509AvailabilityTarget: x509AvailabilityTarget,
	}
}

// ShouldFallbackX509DefaultRotation returns true if the availability target is configured but the value is not enough against the SVID lifetime.
func (rs *RotationStrategy) ShouldFallbackX509DefaultRotation(lifetime time.Duration) bool {
	if rs.x509AvailabilityTarget == 0 {
		// x509AvailabilityTarget is not configured
		return false
	}
	return shouldFallbackX509Default(lifetime, rs.x509AvailabilityTarget)
}

// ShouldRotateX509 determines if a given SVID should be rotated, based
// on presented current time, and the certificate's expiration.
func (rs *RotationStrategy) ShouldRotateX509(now time.Time, cert *x509.Certificate) bool {
	return shouldRotateX509(now, cert.NotBefore, cert.NotAfter, rs.x509AvailabilityTarget)
}

// X509Expired returns true if the given X509 cert has expired
func X509Expired(now time.Time, cert *x509.Certificate) bool {
	return now.After(cert.NotAfter)
}

// JWTSVIDExpiresSoon determines if the given JWT SVID should be rotated
// based on presented current time, the JWT's expiration.
// Also returns true if the JWT is already expired.
func (rs *RotationStrategy) JWTSVIDExpiresSoon(svid *client.JWTSVID, now time.Time) bool {
	if JWTSVIDExpired(svid, now) {
		return true
	}

	// if the SVID has less than half of its lifetime left or reaches the availability target,
	// consider it as expiring soon
	return shouldRotateJWT(now, svid.IssuedAt, svid.ExpiresAt)
}

// JWTSVIDExpired returns true if the given SVID is expired.
func JWTSVIDExpired(svid *client.JWTSVID, now time.Time) bool {
	return !now.Before(svid.ExpiresAt)
}

func shouldRotateX509(now, beginTime, expiryTime time.Time, availabilityTarget time.Duration) bool {
	ttl := expiryTime.Sub(now)
	// return true quickly if the expiry is already met.
	if ttl <= 0 {
		return true
	}

	lifetime := expiryTime.Sub(beginTime)
	if shouldRotateByAvailabilityTarget(ttl, lifetime, availabilityTarget) {
		return true
	}

	// fall back the default rotation strategy.
	return shouldRotateByHalf(ttl, lifetime)
}

func shouldRotateJWT(now, beginTime, expiryTime time.Time) bool {
	ttl := expiryTime.Sub(now)
	// return true quickly if the expiry is already met.
	if ttl <= 0 {
		return true
	}

	lifetime := expiryTime.Sub(beginTime)
	return shouldRotateByHalf(ttl, lifetime)
}

// jitterHalfLifeDelta is a calculated delta centered to the half-life of the SVID.
// It's to spread out the renewal of SVID rotations to avoid spiky renewal requests.
func jitterHalfLifeDelta(halfLife time.Duration) time.Duration {
	return halfLife / 10
}

func halfLife(lifetime time.Duration) time.Duration {
	return lifetime / 2
}

// calculateJitteredHalfLife calculates jitter of the half-life of the SVID.
// The jitter is calculated as ± 10% of the half-life of the SVID.
func calculateJitteredHalfLife(lifetime time.Duration) time.Duration {
	halfLife := halfLife(lifetime)
	delta := jitterHalfLifeDelta(halfLife)
	minHalfLife := halfLife - delta
	return time.Duration(rand.Int63n(int64(delta)*2) + int64(minHalfLife)) //nolint // gosec: no need for cryptographic randomness here
}

// calculateJitteredAvailabilityTarget calculates jitter of the availability target.
// The jitter is calculated as 0 ~ +10min of the availability target.
func calculateJitteredAvailabilityTarget(availabilityTarget time.Duration) time.Duration {
	return time.Duration(rand.Int63n(int64(10*time.Minute)) + int64(availabilityTarget)) //nolint // gosec: no need for cryptographic randomness here
}

func shouldRotateByAvailabilityTarget(ttl, lifetime, availabilityTarget time.Duration) bool {
	if availabilityTarget == 0 {
		return false
	}

	if shouldFallbackX509Default(lifetime, availabilityTarget) {
		return false
	}

	jitteredAvailabilityTarget := calculateJitteredAvailabilityTarget(availabilityTarget)
	return ttl <= jitteredAvailabilityTarget
}

func shouldRotateByHalf(ttl, lifetime time.Duration) bool {
	// calculate a jitter delta to spread out rotations
	jitteredHalfLife := calculateJitteredHalfLife(lifetime)
	return ttl <= jitteredHalfLife
}

func shouldFallbackX509Default(lifetime, availabilityTarget time.Duration) bool {
	// if the grace period less than the threshold, it should be felt back to the default rotation strategy
	gracePeriod := lifetime - availabilityTarget
	return gracePeriod <= gracePeriodThreshold
}
