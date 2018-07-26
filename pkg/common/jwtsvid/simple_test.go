package jwtsvid

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/suite"
)

const (
	fakeSpiffeID = "spiffe://example.org/blog"
)

var (
	ctx           = context.Background()
	fakeAudience  = []string{"AUDIENCE"}
	fakeAudiences = []string{"AUDIENCE1", "AUDIENCE2"}

	keyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgt/OIyb8Ossz/5bNk
XtnzFe1T2d0D9quX9Loi1O55b8yhRANCAATDe/2d6z+P095I3dIkocKr4b3zAy+1
qQDuoXqa8i3YOPk5fLib4ORzqD9NJFcrKjI+LLtipQe9yu/eY1K0yhBa
-----END PRIVATE KEY-----
`)

	otherKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNp9vQd+cdlQhou4s
6WFzVoRLAJP5pnWDISjqlvVIC02hRANCAASRSf3EdTX910uhqorzehrqi9I48rj5
cM3DIfiWwosiykmhI0BmwtTWVD0kIFm7Mhf5XXP03Dj76UjImTLiQduQ
-----END PRIVATE KEY-----
`)
)

func TestSimpleToken(t *testing.T) {
	suite.Run(t, new(SimpleTokenSuite))
}

type SimpleTokenSuite struct {
	suite.Suite

	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	bundle SimpleTrustBundle
}

func (s *SimpleTokenSuite) SetupTest() {
	s.key = s.loadKey(keyPEM)
	s.cert = s.signCert(s.key, createCertificateTemplate(time.Hour))
	s.bundle = NewSimpleTrustBundle("example.org", []*x509.Certificate{s.cert})
}

func (s *SimpleTokenSuite) loadKey(pemBytes []byte) *ecdsa.PrivateKey {
	block, rest := pem.Decode(pemBytes)
	s.Require().Empty(rest)
	s.Require().NotNil(block)
	rawKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	s.Require().NoError(err)
	key, ok := rawKey.(*ecdsa.PrivateKey)
	s.Require().True(ok)
	return key
}

func (s *SimpleTokenSuite) signCert(key *ecdsa.PrivateKey, template *x509.Certificate) *x509.Certificate {
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	s.Require().NoError(err)
	cert, err := x509.ParseCertificate(certDER)
	s.Require().NoError(err)
	return cert
}

func (s *SimpleTokenSuite) TestSignAndValidate() {
	token, err := SignSimpleToken(fakeSpiffeID, fakeAudience, time.Now().Add(time.Hour), s.key, s.cert)
	s.Require().NoError(err)
	s.Require().NotEmpty(token)

	claims, err := ValidateSimpleToken(ctx, token, s.bundle, fakeAudience[0])
	s.Require().NoError(err)
	s.Require().NotEmpty(claims)
}

func (s *SimpleTokenSuite) TestSignAndValidateWithAudienceList() {
	token, err := SignSimpleToken(fakeSpiffeID, fakeAudiences, time.Now().Add(time.Hour), s.key, s.cert)
	s.Require().NoError(err)
	s.Require().NotEmpty(token)

	claims, err := ValidateSimpleToken(ctx, token, s.bundle, fakeAudiences[0])
	s.Require().NoError(err)
	s.Require().NotEmpty(claims)
}

func (s *SimpleTokenSuite) TestSignWithNoExpiration() {
	_, err := SignSimpleToken(fakeSpiffeID, fakeAudience, time.Time{}, s.key, s.cert)
	s.Require().EqualError(err, "expiration is required")
}

func (s *SimpleTokenSuite) TestSignMismatchedKeypair() {
	key := s.loadKey(otherKeyPEM)
	cert := s.signCert(key, createCertificateTemplate(time.Hour))

	_, err := SignSimpleToken(fakeSpiffeID, fakeAudience, time.Now(), key, s.cert)
	s.Require().EqualError(err, "certificate does not match signing key")

	_, err = SignSimpleToken(fakeSpiffeID, fakeAudience, time.Now(), s.key, cert)
	s.Require().EqualError(err, "certificate does not match signing key")
}

func (s *SimpleTokenSuite) TestSignInvalidSpiffeID() {
	// missing ID
	_, err := SignSimpleToken("", fakeAudience, time.Now(), s.key, s.cert)
	s.requireErrorContains(err, "is not a valid SPIFFE ID: SPIFFE ID is empty")

	// not a spiffe ID
	_, err = SignSimpleToken("sparfe://example.org", fakeAudience, time.Now(), s.key, s.cert)
	s.requireErrorContains(err, "is not a valid SPIFFE ID: invalid scheme")
}

func (s *SimpleTokenSuite) TestSignNoAudience() {
	_, err := SignSimpleToken(fakeSpiffeID, nil, time.Now().Add(time.Hour), s.key, s.cert)
	s.Require().EqualError(err, "audience is required")
}

func (s *SimpleTokenSuite) TestValidateBadAlgorithm() {
	token := jwt.New(jwt.SigningMethodHS256)
	tokenString, err := token.SignedString([]byte("BLAH"))
	s.Require().NoError(err)

	claims, err := ValidateSimpleToken(ctx, tokenString, s.bundle, fakeAudience[0])
	s.Require().EqualError(err, "unexpected token signature algorithm: HS256")
	s.Require().Nil(claims)
}

func (s *SimpleTokenSuite) TestValidateMissingThumbprint() {
	token := jwt.New(jwt.SigningMethodES256)
	tokenString, err := token.SignedString(s.key)
	s.Require().NoError(err)

	claims, err := ValidateSimpleToken(ctx, tokenString, s.bundle, fakeAudience[0])
	s.Require().EqualError(err, "token missing certificate thumbprint")
	s.Require().Nil(claims)
}

func (s *SimpleTokenSuite) TestValidateExpiredToken() {
	token, err := SignSimpleToken(fakeSpiffeID, fakeAudience, time.Now().Add(-time.Hour), s.key, s.cert)
	s.Require().NoError(err)
	s.Require().NotEmpty(token)

	claims, err := ValidateSimpleToken(ctx, token, s.bundle, fakeAudience[0])
	s.Require().EqualError(err, "Token is expired")
	s.Require().Nil(claims)
}

func (s *SimpleTokenSuite) TestValidateNoSubject() {
	token := jwt.New(jwt.SigningMethodES256)
	token.Header["x5t#S256"] = certificateThumbprint(s.cert)
	tokenString, err := token.SignedString(s.key)
	s.Require().NoError(err)

	claims, err := ValidateSimpleToken(ctx, tokenString, s.bundle, "FOO")
	s.Require().EqualError(err, "token missing subject claim")
	s.Require().Nil(claims)
}

func (s *SimpleTokenSuite) TestValidateSubjectNotForDomain() {
	token := jwt.New(jwt.SigningMethodES256)
	token.Header["x5t#S256"] = certificateThumbprint(s.cert)
	token.Claims = jwt.MapClaims{
		"sub": "spiffe://other.org",
	}
	tokenString, err := token.SignedString(s.key)
	s.Require().NoError(err)

	claims, err := ValidateSimpleToken(ctx, tokenString, s.bundle, "FOO")
	s.Require().EqualError(err, `token has in invalid subject claim: "spiffe://other.org" does not belong to trust domain "example.org"`)
	s.Require().Nil(claims)
}

func (s *SimpleTokenSuite) TestValidateNoAudience() {
	token := jwt.New(jwt.SigningMethodES256)
	token.Header["x5t#S256"] = certificateThumbprint(s.cert)
	token.Claims = jwt.MapClaims{
		"sub": "spiffe://example.org/blog",
	}
	tokenString, err := token.SignedString(s.key)
	s.Require().NoError(err)

	claims, err := ValidateSimpleToken(ctx, tokenString, s.bundle, "FOO")
	s.Require().EqualError(err, "token missing audience claim")
	s.Require().Nil(claims)
}

func (s *SimpleTokenSuite) TestValidateUnexpectedAudience() {
	token, err := SignSimpleToken(fakeSpiffeID, fakeAudience, time.Now().Add(time.Hour), s.key, s.cert)
	s.Require().NoError(err)
	s.Require().NotEmpty(token)

	claims, err := ValidateSimpleToken(ctx, token, s.bundle, "FOO")
	s.Require().EqualError(err, `expected audience "FOO" (audience="AUDIENCE")`)
	s.Require().Nil(claims)
}

func (s *SimpleTokenSuite) TestValidateUnexpectedAudienceList() {
	token, err := SignSimpleToken(fakeSpiffeID, fakeAudiences, time.Now().Add(time.Hour), s.key, s.cert)
	s.Require().NoError(err)
	s.Require().NotEmpty(token)

	claims, err := ValidateSimpleToken(ctx, token, s.bundle, "AUDIENCE3")
	s.Require().EqualError(err, `expected audience "AUDIENCE3" (audience=["AUDIENCE1" "AUDIENCE2"])`)
	s.Require().Nil(claims)
}

func (s *SimpleTokenSuite) TestValidateCertificateNotFound() {
	token, err := SignSimpleToken(fakeSpiffeID, fakeAudience, time.Now().Add(time.Hour), s.key, s.cert)
	s.Require().NoError(err)
	s.Require().NotEmpty(token)

	bundle := NewSimpleTrustBundle("example.org", nil)
	claims, err := ValidateSimpleToken(ctx, token, bundle, fakeAudience[0])
	s.Require().EqualError(err, "signing certificate not found in trust bundle")
	s.Require().Nil(claims)
}

func (s *SimpleTokenSuite) TestValidateCertificateIsBadOrExpired() {
	testBadCert := func(tmpl *x509.Certificate, expectedErr string) {
		cert := s.signCert(s.key, tmpl)
		bundle := NewSimpleTrustBundle("example.org", []*x509.Certificate{cert})
		token, err := SignSimpleToken(fakeSpiffeID, fakeAudience, time.Now().Add(time.Hour), s.key, cert)
		s.Require().NoError(err)
		s.Require().NotEmpty(token)
		claims, err := ValidateSimpleToken(ctx, token, bundle, fakeAudience[0])
		s.Require().EqualError(err, expectedErr)
		s.Require().Nil(claims)
	}

	tmpl := createCertificateTemplate(time.Hour)
	tmpl.IsCA = true
	testBadCert(tmpl, "signing certificate cannot be a CA")

	tmpl = createCertificateTemplate(-time.Hour)
	testBadCert(tmpl, "signing certificate is expired")

	tmpl = createCertificateTemplate(time.Hour)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	testBadCert(tmpl, "signing certificate cannot have any key usage")
}

func (s *SimpleTokenSuite) requireErrorContains(err error, contains string) {
	s.Require().Error(err)
	s.Require().Contains(err.Error(), contains)
}

func createCertificateTemplate(notAfter time.Duration) *x509.Certificate {
	template := CreateCertificateTemplate(&x509.Certificate{
		NotAfter: time.Now().Add(notAfter),
	})
	template.SerialNumber = big.NewInt(1)
	return template
}
