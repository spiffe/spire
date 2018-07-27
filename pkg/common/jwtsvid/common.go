package jwtsvid

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

func audienceClaim(audience []string) interface{} {
	if len(audience) == 1 {
		return audience[0]
	}
	return audience
}

func GetTokenExpiry(token string) (time.Time, error) {
	claims := new(jwt.StandardClaims)
	_, _, err := new(jwt.Parser).ParseUnverified(token, claims)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(claims.ExpiresAt, 0).UTC(), nil
}
