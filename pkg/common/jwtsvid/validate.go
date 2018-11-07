package jwtsvid

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/spiffe/spire/pkg/common/idutil"
)

type KeyStore interface {
	FindPublicKey(ctx context.Context, trustDomainId, kid string) (crypto.PublicKey, error)
}

type keyStore struct {
	trustDomainKeys map[string]map[string]crypto.PublicKey
}

func NewKeyStore(trustDomainKeys map[string]map[string]crypto.PublicKey) KeyStore {
	return &keyStore{
		trustDomainKeys: trustDomainKeys,
	}
}

func (t *keyStore) FindPublicKey(ctx context.Context, trustDomainId, keyID string) (crypto.PublicKey, error) {
	publicKeys, ok := t.trustDomainKeys[trustDomainId]
	if !ok {
		return nil, fmt.Errorf("no keys found for trust domain %q", trustDomainId)
	}
	publicKey, ok := publicKeys[keyID]
	if !ok {
		return nil, fmt.Errorf("public key %q not found in trust domain %q", keyID, trustDomainId)
	}
	return publicKey, nil
}

func getSigningKey(ctx context.Context, keyStore KeyStore, t *jwt.Token, claims jwt.MapClaims) (string, interface{}, error) {
	if t.Method.Alg() != jwt.SigningMethodES256.Alg() {
		return "", nil, fmt.Errorf("unexpected token signature algorithm: %s", t.Method.Alg())
	}
	keyID, _ := t.Header[keyIDHeader].(string)
	if keyID == "" {
		return "", nil, errors.New("token missing key id")
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", nil, errors.New("token missing subject claim")
	}

	id, err := idutil.ParseSpiffeID(sub, idutil.AllowAnyTrustDomainWorkload())
	if err != nil {
		return "", nil, fmt.Errorf("token has in invalid subject claim: %v", err)
	}

	// construct the trust domain id from the spiffe id
	trustDomainId := *id
	trustDomainId.Path = ""

	key, err := keyStore.FindPublicKey(ctx, trustDomainId.String(), keyID)
	if err != nil {
		return "", nil, err
	}

	return id.String(), key, nil
}

func ValidateToken(ctx context.Context, token string, keyStore KeyStore, audience []string) (string, jwt.MapClaims, error) {
	var spiffeID string
	claims := make(jwt.MapClaims)
	if _, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (key interface{}, err error) {
		spiffeID, key, err = getSigningKey(ctx, keyStore, t, claims)
		return key, err
	}); err != nil {
		return "", nil, err
	}

	switch audienceClaim := claims["aud"].(type) {
	case []interface{}:
		found := false
		for _, audValue := range audienceClaim {
			if aud, ok := audValue.(string); ok && stringInList(aud, audience) {
				found = true
				break
			}
		}
		if !found {
			return "", nil, fmt.Errorf("expected audience in %q (audience=%q)", audience, audienceClaim)
		}
	case string:
		if !stringInList(audienceClaim, audience) {
			return "", nil, fmt.Errorf("expected audience in %q (audience=%q)", audience, audienceClaim)
		}
	default:
		return "", nil, errors.New("token missing audience claim")
	}
	return spiffeID, claims, nil
}

func stringInList(s string, ss []string) bool {
	for _, candidate := range ss {
		if s == candidate {
			return true
		}
	}
	return false
}
