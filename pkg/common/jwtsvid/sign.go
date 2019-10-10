package jwtsvid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/zeebo/errs"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	keyIDHeader = "kid"
)

type SignerConfig struct {
	Clock clock.Clock

	// Issuer is used as the value of the issuer (iss) claim, if set.
	Issuer string
}

type Signer struct {
	c SignerConfig
}

func NewSigner(config SignerConfig) *Signer {
	if config.Clock == nil {
		config.Clock = clock.New()
	}
	return &Signer{
		c: config,
	}
}

func (s *Signer) SignToken(spiffeID string, audience []string, expires time.Time, signer crypto.Signer, kid string) (string, error) {
	if err := idutil.ValidateSpiffeID(spiffeID, idutil.AllowAnyTrustDomainWorkload()); err != nil {
		return "", err
	}

	audience = pruneEmptyValues(audience)

	if expires.IsZero() {
		return "", errors.New("expiration is required")
	}
	if len(audience) == 0 {
		return "", errors.New("audience is required")
	}
	if len(kid) == 0 {
		return "", errors.New("kid is required")
	}

	claims := jwt.Claims{
		Subject:  spiffeID,
		Issuer:   s.c.Issuer,
		Expiry:   jwt.NewNumericDate(expires),
		Audience: audience,
		IssuedAt: jwt.NewNumericDate(s.c.Clock.Now()),
	}

	var alg jose.SignatureAlgorithm
	switch publicKey := signer.Public().(type) {
	case *rsa.PublicKey:
		// Prevent the use of keys smaller than 2048 bits
		if publicKey.Size() < 256 {
			return "", errs.New("unsupported RSA key size: %d", publicKey.Size())
		}
		alg = jose.RS256
	case *ecdsa.PublicKey:
		params := publicKey.Params()
		switch params.BitSize {
		case 256:
			alg = jose.ES256
		case 384:
			alg = jose.ES384
		default:
			return "", errs.New("unable to determine signature algorithm for EC public key size %d", params.BitSize)
		}
	default:
		return "", errs.New("unable to determine signature algorithm for public key type %T", publicKey)
	}

	jwtSigner, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: alg,
			Key: jose.JSONWebKey{
				Key:   cryptosigner.Opaque(signer),
				KeyID: kid,
			},
		},
		new(jose.SignerOptions).WithType("JWT"),
	)
	if err != nil {
		return "", errs.Wrap(err)
	}

	signedToken, err := jwt.Signed(jwtSigner).Claims(claims).CompactSerialize()
	if err != nil {
		return "", errs.Wrap(err)
	}

	return signedToken, nil
}

func pruneEmptyValues(values []string) []string {
	pruned := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			pruned = append(pruned, value)
		}
	}
	return pruned
}
