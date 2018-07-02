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

	expiredKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
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

	cert          *x509.Certificate
	key           *ecdsa.PrivateKey
	bundle        SimpleTrustBundle
	expiredCert   *x509.Certificate
	expiredKey    *ecdsa.PrivateKey
	expiredBundle SimpleTrustBundle
}

func (s *SimpleTokenSuite) SetupTest() {
	s.key = s.loadKey(keyPEM)
	s.cert = s.signCert(s.key, createCertificateTemplate(time.Hour))
	s.bundle = NewSimpleTrustBundle([]*x509.Certificate{s.cert})
	s.expiredKey = s.loadKey(expiredKeyPEM)
	s.expiredCert = s.signCert(s.expiredKey, createCertificateTemplate(-time.Hour))
	s.expiredBundle = NewSimpleTrustBundle([]*x509.Certificate{s.expiredCert})
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
	_, err := SignSimpleToken(fakeSpiffeID, fakeAudience, time.Now(), s.expiredKey, s.cert)
	s.Require().EqualError(err, "certificate does not match private key")

	_, err = SignSimpleToken(fakeSpiffeID, fakeAudience, time.Now(), s.key, s.expiredCert)
	s.Require().EqualError(err, "certificate does not match private key")
}

func (s *SimpleTokenSuite) TestSignInvalidSpiffeID() {
	// missing ID
	_, err := SignSimpleToken("", fakeAudience, time.Now(), s.key, s.cert)
	s.requireErrorContains(err, "is not a valid workload SPIFFE ID: SPIFFE ID is empty")

	// only workload spiffe ID's are acceptable subjects
	_, err = SignSimpleToken("spiffe://example.org", fakeAudience, time.Now(), s.key, s.cert)
	s.requireErrorContains(err, "is not a valid workload SPIFFE ID: path is empty")
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

func (s *SimpleTokenSuite) TestValidateNoAudience() {
	token := jwt.New(jwt.SigningMethodES256)
	token.Header["x5t#S256"] = certificateThumbprint(s.cert)
	tokenString, err := token.SignedString(s.key)
	s.Require().NoError(err)

	claims, err := ValidateSimpleToken(ctx, tokenString, s.bundle, "FOO")
	s.Require().EqualError(err, "missing audience claim")
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

	claims, err := ValidateSimpleToken(ctx, token, s.expiredBundle, fakeAudience[0])
	s.Require().EqualError(err, "signing certificate not found in trust bundle")
	s.Require().Nil(claims)
}

func (s *SimpleTokenSuite) TestValidateCertificateExpired() {
	token, err := SignSimpleToken(fakeSpiffeID, fakeAudience, time.Now().Add(time.Hour), s.expiredKey, s.expiredCert)
	s.Require().NoError(err)
	s.Require().NotEmpty(token)

	claims, err := ValidateSimpleToken(ctx, token, s.expiredBundle, fakeAudience[0])
	s.Require().EqualError(err, "signing certificate is expired")
	s.Require().Nil(claims)
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
