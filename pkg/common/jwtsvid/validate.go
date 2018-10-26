package jwtsvid

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/spiffe/spire/pkg/common/idutil"
)

type TrustBundle interface {
	TrustDomain() string
	FindPublicKey(ctx context.Context, kid string) (crypto.PublicKey, error)
}

type trustBundle struct {
	trustDomain string
	publicKeys  map[string]crypto.PublicKey
}

func NewTrustBundle(trustDomain string, publicKeys map[string]crypto.PublicKey) TrustBundle {
	t := &trustBundle{
		trustDomain: trustDomain,
		publicKeys:  publicKeys,
	}
	return t
}

func (t *trustBundle) TrustDomain() string {
	return t.trustDomain
}

func (t *trustBundle) FindPublicKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	publicKey, ok := t.publicKeys[kid]
	if !ok {
		return nil, errors.New("public key not found in trust bundle")
	}
	return publicKey, nil
}

func getSigningKey(ctx context.Context, t *jwt.Token, trustBundle TrustBundle) (interface{}, error) {
	if t.Method.Alg() != jwt.SigningMethodES256.Alg() {
		return nil, fmt.Errorf("unexpected token signature algorithm: %s", t.Method.Alg())
	}
	kid, _ := t.Header[keyIDHeader].(string)
	if kid == "" {
		return nil, errors.New("token missing key id")
	}
	return trustBundle.FindPublicKey(ctx, kid)
}

func ValidateToken(ctx context.Context, token string, trustBundle TrustBundle, audience string) (jwt.MapClaims, error) {
	claims := make(jwt.MapClaims)
	if _, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		return getSigningKey(ctx, t, trustBundle)
	}); err != nil {
		return nil, err
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, errors.New("token missing subject claim")
	}
	if err := idutil.ValidateSpiffeID(sub, idutil.AllowTrustDomainWorkload(trustBundle.TrustDomain())); err != nil {
		return nil, fmt.Errorf("token has in invalid subject claim: %v", err)
	}

	switch audienceClaim := claims["aud"].(type) {
	case []interface{}:
		found := false
		for _, audValue := range audienceClaim {
			if aud, ok := audValue.(string); ok && aud == audience {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("expected audience %q (audience=%q)", audience, audienceClaim)
		}
	case string:
		if audienceClaim != audience {
			return nil, fmt.Errorf("expected audience %q (audience=%q)", audience, audienceClaim)
		}
	default:
		return nil, errors.New("token missing audience claim")
	}
	return claims, nil
}
