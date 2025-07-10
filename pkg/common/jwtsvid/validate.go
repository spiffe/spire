package jwtsvid

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type KeyStore interface {
	FindPublicKey(ctx context.Context, td spiffeid.TrustDomain, kid string) (crypto.PublicKey, error)
}

type keyStore struct {
	trustDomainKeys map[spiffeid.TrustDomain]map[string]crypto.PublicKey
}

func NewKeyStore(trustDomainKeys map[spiffeid.TrustDomain]map[string]crypto.PublicKey) KeyStore {
	return &keyStore{
		trustDomainKeys: trustDomainKeys,
	}
}

func (t *keyStore) FindPublicKey(_ context.Context, td spiffeid.TrustDomain, keyID string) (crypto.PublicKey, error) {
	publicKeys, ok := t.trustDomainKeys[td]
	if !ok {
		return nil, fmt.Errorf("no keys found for trust domain %q", td)
	}
	publicKey, ok := publicKeys[keyID]
	if !ok {
		return nil, fmt.Errorf("public key %q not found in trust domain %q", keyID, td)
	}
	return publicKey, nil
}

func ValidateToken(ctx context.Context, token string, keyStore KeyStore, audience []string) (spiffeid.ID, map[string]any, error) {
	tok, err := jwt.ParseSigned(token, AllowedSignatureAlgorithms)
	if err != nil {
		return spiffeid.ID{}, nil, fmt.Errorf("unable to parse JWT token: %w", err)
	}

	if len(tok.Headers) != 1 {
		return spiffeid.ID{}, nil, fmt.Errorf("expected a single token header; got %d", len(tok.Headers))
	}

	// Obtain the key ID from the header
	keyID := tok.Headers[0].KeyID
	if keyID == "" {
		return spiffeid.ID{}, nil, errors.New("token header missing key id")
	}

	// Parse out the unverified claims. We need to look up the key by the trust
	// domain of the SPIFFE ID. We'll verify the signature on the claims below
	// when creating the generic map of claims that we return to the caller.
	var claims jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return spiffeid.ID{}, nil, err
	}
	if claims.Subject == "" {
		return spiffeid.ID{}, nil, errors.New("token missing subject claim")
	}
	if claims.Expiry == nil {
		return spiffeid.ID{}, nil, errors.New("token missing exp claim")
	}
	spiffeID, err := spiffeid.FromString(claims.Subject)
	if err != nil {
		return spiffeid.ID{}, nil, fmt.Errorf("token has in invalid subject claim: %w", err)
	}

	// Construct the trust domain id from the SPIFFE ID and look up key by ID
	key, err := keyStore.FindPublicKey(ctx, spiffeID.TrustDomain(), keyID)
	if err != nil {
		return spiffeid.ID{}, nil, err
	}

	// Now obtain the generic claims map verified using the obtained key
	claimsMap := make(map[string]any)
	if err := tok.Claims(key, &claimsMap); err != nil {
		return spiffeid.ID{}, nil, err
	}

	// Now that the signature over the claims has been verified, validate the
	// standard claims.
	if err := claims.Validate(jwt.Expected{
		AnyAudience: audience,
		Time:        time.Now(),
	}); err != nil {
		// Convert expected validation errors for pretty errors
		switch {
		case errors.Is(err, jwt.ErrExpired):
			err = errors.New("token has expired")
		case errors.Is(err, jwt.ErrInvalidAudience):
			err = fmt.Errorf("expected audience in %q (audience=%q)", audience, claims.Audience)
		}
		return spiffeid.ID{}, nil, err
	}

	return spiffeID, claimsMap, nil
}
