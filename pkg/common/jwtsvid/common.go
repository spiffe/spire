package jwtsvid

import (
	"crypto/ecdsa"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

func audienceClaim(audience []string) interface{} {
	if len(audience) == 1 {
		return audience[0]
	}
	return audience
}

func ecdsaKeyMatches(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) bool {
	return publicKey.X.Cmp(privateKey.X) == 0 && publicKey.Y.Cmp(privateKey.Y) == 0
}

func GetTokenExpiry(token string) (time.Time, error) {
	claims := new(jwt.StandardClaims)
	_, _, err := new(jwt.Parser).ParseUnverified(token, claims)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(claims.ExpiresAt, 0), nil
}
