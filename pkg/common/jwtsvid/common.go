package jwtsvid

import (
	"errors"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

func audienceClaim(audience []string) interface{} {
	if len(audience) == 1 {
		return audience[0]
	}
	return audience
}

func GetTokenExpiry(token string) (time.Time, time.Time, error) {
	claims := new(jwt.StandardClaims)
	_, _, err := new(jwt.Parser).ParseUnverified(token, claims)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if claims.IssuedAt == 0 {
		return time.Time{}, time.Time{}, errors.New("JWT missing iat claim")
	}
	if claims.ExpiresAt == 0 {
		return time.Time{}, time.Time{}, errors.New("JWT missing exp claim")
	}

	issuedAt := time.Unix(claims.IssuedAt, 0).UTC()
	expiresAt := time.Unix(claims.ExpiresAt, 0).UTC()
	return issuedAt, expiresAt, nil
}
