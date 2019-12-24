package jwtsvid

import (
	"errors"
	"time"

	"github.com/zeebo/errs"
	"gopkg.in/square/go-jose.v2/jwt"
)

func GetTokenExpiry(token string) (time.Time, time.Time, error) {
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return time.Time{}, time.Time{}, errs.Wrap(err)
	}

	claims := jwt.Claims{}
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return time.Time{}, time.Time{}, errs.Wrap(err)
	}
	if claims.IssuedAt == nil {
		return time.Time{}, time.Time{}, errors.New("JWT missing iat claim")
	}
	if claims.Expiry == nil {
		return time.Time{}, time.Time{}, errors.New("JWT missing exp claim")
	}

	issuedAt := claims.IssuedAt.Time().UTC()
	expiresAt := claims.Expiry.Time().UTC()
	return issuedAt, expiresAt, nil
}
