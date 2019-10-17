package jwtsvid

import (
	"context"
	"crypto"
	"fmt"
	"time"

	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/zeebo/errs"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
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

func ValidateToken(ctx context.Context, token string, keyStore KeyStore, audience []string) (string, map[string]interface{}, error) {
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return "", nil, errs.New("unable to parse JWT token")
	}

	if len(tok.Headers) != 1 {
		return "", nil, errs.New("expected a single token header; got %d", len(tok.Headers))
	}

	// Make sure it has an algorithm supported by JWT-SVID
	alg := tok.Headers[0].Algorithm
	switch jose.SignatureAlgorithm(alg) {
	case jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512:
	default:
		return "", nil, errs.New("unsupported token signature algorithm %q", alg)
	}

	// Obtain the key ID from the header
	keyID := tok.Headers[0].KeyID
	if keyID == "" {
		return "", nil, errs.New("token header missing key id")
	}

	// Parse out the unverified claims. We need to look up the key by the trust
	// domain of the SPIFFE ID. We'll verify the signature on the claims below
	// when creating the generic map of claims that we return to the caller.
	var claims jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return "", nil, errs.Wrap(err)
	}
	if claims.Subject == "" {
		return "", nil, errs.New("token missing subject claim")
	}
	spiffeID, err := idutil.ParseSpiffeID(claims.Subject, idutil.AllowAnyTrustDomainWorkload())
	if err != nil {
		return "", nil, errs.New("token has in invalid subject claim: %v", err)
	}

	// Construct the trust domain id from the SPIFFE ID and look up key by ID
	trustDomainId := *spiffeID
	trustDomainId.Path = ""
	key, err := keyStore.FindPublicKey(ctx, trustDomainId.String(), keyID)
	if err != nil {
		return "", nil, err
	}

	// Now obtain the generic claims map verified using the obtained key
	claimsMap := make(map[string]interface{})
	if err := tok.Claims(key, &claimsMap); err != nil {
		return "", nil, errs.Wrap(err)
	}

	// Now that the signature over the claims has been verified, validate the
	// standard claims.
	if err := claims.Validate(jwt.Expected{
		Audience: audience,
		Time:     time.Now(),
	}); err != nil {
		// Convert expected validation errors for pretty errors
		switch err {
		case jwt.ErrExpired:
			err = errs.New("token has expired")
		case jwt.ErrInvalidAudience:
			err = errs.New("expected audience in %q (audience=%q)", audience, claims.Audience)
		default:
			err = errs.Wrap(err)
		}
		return "", nil, err
	}

	return spiffeID.String(), claimsMap, nil
}
