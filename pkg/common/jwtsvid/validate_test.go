package jwtsvid

import (
	"context"
	"crypto"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	ctx           = context.Background()
	fakeSpiffeID  = spiffeid.RequireFromString("spiffe://example.org/blog")
	fakeAudience  = []string{"AUDIENCE"}
	fakeAudiences = []string{"AUDIENCE1", "AUDIENCE2"}

	ec256Key   = testkey.MustEC256()
	ec384Key   = testkey.MustEC384()
	rsa2048Key = testkey.MustRSA2048()
	rsa4096Key = testkey.MustRSA4096()
)

func TestToken(t *testing.T) {
	spiretest.Run(t, new(TokenSuite))
}

type TokenSuite struct {
	spiretest.Suite

	bundle KeyStore
	clock  *clock.Mock
}

func (s *TokenSuite) SetupTest() {
	s.bundle = NewKeyStore(map[spiffeid.TrustDomain]map[string]crypto.PublicKey{
		spiffeid.RequireTrustDomainFromString("spiffe://example.org"): {
			"ec256Key":   ec256Key.Public(),
			"ec384Key":   ec384Key.Public(),
			"rsa2048Key": rsa2048Key.Public(),
			"rsa4096Key": rsa4096Key.Public(),
		},
	})
	s.clock = clock.NewMock(s.T())
}

func (s *TokenSuite) TestDifferentKeys() {
	testCases := []struct {
		kid string
		key crypto.Signer
	}{
		{
			kid: "ec256Key",
			key: ec256Key,
		},
		{
			kid: "ec384Key",
			key: ec384Key,
		},
		{
			kid: "rsa2048Key",
			key: rsa2048Key,
		},
		{
			kid: "rsa4096Key",
			key: rsa4096Key,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase // alias loop variable as it is used in the closure
		s.T().Run(testCase.kid, func(t *testing.T) {
			token := s.signJWTSVID(fakeSpiffeID, fakeAudience, time.Now().Add(time.Hour), testCase.key, testCase.kid)

			spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, fakeAudience[0:1])
			require.NoError(t, err)
			require.Equal(t, fakeSpiffeID, spiffeID)
			require.NotEmpty(t, claims)
		})
	}
}

func (s *TokenSuite) TestValidateWithAudienceList() {
	token := s.signJWTSVID(fakeSpiffeID, fakeAudiences, time.Now().Add(time.Hour), ec256Key, "ec256Key")

	spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, fakeAudiences[0:1])
	s.Require().NoError(err)
	s.Require().Equal(fakeSpiffeID, spiffeID)
	s.Require().NotEmpty(claims)
}

func (s *TokenSuite) TestValidateBadAlgorithm() {
	token := s.signToken(jose.HS256, []byte("BLAH"), jwt.Claims{})

	spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, fakeAudience[0:1])
	s.Require().EqualError(err, `unsupported token signature algorithm "HS256"`)
	s.Require().Empty(spiffeID)
	s.Require().Nil(claims)
}

func (s *TokenSuite) TestValidateMissingThumbprint() {
	token := s.signToken(jose.ES256, ec256Key, jwt.Claims{})

	spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, fakeAudience[0:1])
	s.Require().EqualError(err, "token header missing key id")
	s.Require().Empty(spiffeID)
	s.Require().Nil(claims)
}

func (s *TokenSuite) TestValidateExpiredToken() {
	token := s.signJWTSVID(fakeSpiffeID, fakeAudience, time.Now().Add(-time.Hour), ec256Key, "ec256Key")

	spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, fakeAudience[0:1])
	s.Require().EqualError(err, "token has expired")
	s.Require().Empty(spiffeID)
	s.Require().Nil(claims)
}

func (s *TokenSuite) TestValidateNoSubject() {
	token := s.signToken(jose.ES256, jose.JSONWebKey{Key: ec256Key, KeyID: "ec256Key"}, jwt.Claims{
		Audience: []string{"audience"},
	})

	spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, []string{"FOO"})
	s.Require().EqualError(err, "token missing subject claim")
	s.Require().Empty(spiffeID)
	s.Require().Nil(claims)
}

func (s *TokenSuite) TestValidateSubjectNotForDomain() {
	token := s.signToken(jose.ES256, jose.JSONWebKey{Key: ec256Key, KeyID: "ec256Key"}, jwt.Claims{
		Subject:  "spiffe://other.org/foo",
		Audience: []string{"audience"},
	})

	spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, []string{"FOO"})
	s.Require().EqualError(err, `no keys found for trust domain "other.org"`)
	s.Require().Empty(spiffeID)
	s.Require().Nil(claims)
}

func (s *TokenSuite) TestValidateNoAudience() {
	token := s.signToken(jose.ES256, jose.JSONWebKey{Key: ec256Key, KeyID: "ec256Key"}, jwt.Claims{
		Subject: fakeSpiffeID.String(),
	})

	spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, []string{"FOO"})
	s.Require().EqualError(err, `expected audience in ["FOO"] (audience=[])`)
	s.Require().Empty(spiffeID)
	s.Require().Nil(claims)
}

func (s *TokenSuite) TestValidateUnexpectedAudience() {
	token := s.signJWTSVID(fakeSpiffeID, fakeAudience, time.Now().Add(time.Hour), ec256Key, "ec256Key")

	spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, []string{"FOO"})
	s.Require().EqualError(err, `expected audience in ["FOO"] (audience=["AUDIENCE"])`)
	s.Require().Empty(spiffeID)
	s.Require().Nil(claims)
}

func (s *TokenSuite) TestValidateUnexpectedAudienceList() {
	token := s.signJWTSVID(fakeSpiffeID, fakeAudiences, time.Now().Add(time.Hour), ec256Key, "ec256Key")

	spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, []string{"AUDIENCE3"})
	s.Require().EqualError(err, `expected audience in ["AUDIENCE3"] (audience=["AUDIENCE1" "AUDIENCE2"])`)
	s.Require().Empty(spiffeID)
	s.Require().Nil(claims)
}

func (s *TokenSuite) TestValidateKeyNotFound() {
	token := s.signJWTSVID(fakeSpiffeID, fakeAudience, time.Now().Add(time.Hour), ec256Key, "whatever")

	spiffeID, claims, err := ValidateToken(ctx, token, s.bundle, fakeAudience[0:1])
	s.Require().EqualError(err, `public key "whatever" not found in trust domain "example.org"`)
	s.Require().Empty(spiffeID)
	s.Require().Nil(claims)
}

func (s *TokenSuite) signToken(alg jose.SignatureAlgorithm, key interface{}, claims jwt.Claims) string {
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: alg,
			Key:       key,
		}, nil)
	s.Require().NoError(err)

	token, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	s.Require().NoError(err)
	return token
}

func (s *TokenSuite) signJWTSVID(id spiffeid.ID, audience []string, expires time.Time, signer crypto.Signer, kid string) string {
	claims := jwt.Claims{
		Subject:  id.String(),
		Expiry:   jwt.NewNumericDate(expires),
		Audience: audience,
		IssuedAt: jwt.NewNumericDate(s.clock.Now()),
	}

	alg, err := cryptoutil.JoseAlgFromPublicKey(signer.Public())
	s.Require().NoError(err)

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
	s.Require().NoError(err)

	signedToken, err := jwt.Signed(jwtSigner).Claims(claims).CompactSerialize()
	s.Require().NoError(err)
	return signedToken
}
