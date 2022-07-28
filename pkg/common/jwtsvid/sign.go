package jwtsvid

import (
	"crypto"
	"errors"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/zeebo/errs"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
)

type SignerConfig struct {
	Clock clock.Clock

	// Issuer is used as the value of the issuer (iss) claim, if set.
	Issuer string

	// VerboseClaims defines whether a verbose 'trust' and 'workload' claim is added to the JWT.
	VerboseClaims bool
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

func (s *Signer) SignToken(id spiffeid.ID, audience []string, expires time.Time, signer crypto.Signer, kid string) (string, error) {
	audience = pruneEmptyValues(audience)

	if id.IsZero() {
		return "", errors.New("id is required")
	}
	if expires.IsZero() {
		return "", errors.New("expiration is required")
	}
	if len(audience) == 0 {
		return "", errors.New("audience is required")
	}
	if len(kid) == 0 {
		return "", errors.New("kid is required")
	}

	var extraClaims []interface{}
	claims := jwt.Claims{
		Subject:  id.String(),
		Issuer:   s.c.Issuer,
		Expiry:   jwt.NewNumericDate(expires),
		Audience: audience,
		IssuedAt: jwt.NewNumericDate(s.c.Clock.Now()),
	}

	if s.c.VerboseClaims {
		verboseClaims := struct {
			TrustDomain   spiffeid.TrustDomain `json:"trust"`
			WorkloadIdent string               `json:"workload"`
		}{
			TrustDomain:   id.TrustDomain(),
			WorkloadIdent: id.Path(),
		}
		extraClaims = append(extraClaims, verboseClaims)
	}

	alg, err := cryptoutil.JoseAlgFromPublicKey(signer.Public())
	if err != nil {
		return "", errs.Wrap(err)
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

	builder := jwt.Signed(jwtSigner).Claims(claims)
	for _, extraClaim := range extraClaims {
		builder = builder.Claims(extraClaim)
	}

	signedToken, err := builder.CompactSerialize()
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
