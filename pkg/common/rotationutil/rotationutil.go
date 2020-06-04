package rotationutil

import (
	"crypto/x509"
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
	lifetime := expiryTime.Sub(beginTime)
	return ttl <= lifetime/2
}
