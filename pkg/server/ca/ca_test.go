package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/memory"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/server/keymanager"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/stretchr/testify/suite"
)

var (
	keyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgt/OIyb8Ossz/5bNk
XtnzFe1T2d0D9quX9Loi1O55b8yhRANCAATDe/2d6z+P095I3dIkocKr4b3zAy+1
qQDuoXqa8i3YOPk5fLib4ORzqD9NJFcrKjI+LLtipQe9yu/eY1K0yhBa
-----END PRIVATE KEY-----
`)
)

func TestCA(t *testing.T) {
	suite.Run(t, new(CATestSuite))
}

type CATestSuite struct {
	suite.Suite

	signer crypto.Signer
	now    time.Time
	ca     *serverCA
}

func (s *CATestSuite) SetupTest() {
	key, err := pemutil.ParseECPrivateKey(keyPEM)
	s.Require().NoError(err)
	s.signer = key
	s.now = time.Now().Truncate(time.Second).UTC()

	km := memory.New()
	x509CASigner, err := cryptoutil.GenerateKeyAndSigner(ctx, km, "x509-CA-FOO", keymanager.KeyAlgorithm_ECDSA_P256)
	s.Require().NoError(err)

	x509CA, err := SelfSignServerCACertificate(x509CASigner, "example.org", pkix.Name{}, time.Now(), time.Now().Add(time.Minute*2))
	s.Require().NoError(err)

	jwtSignerPublicKey, err := cryptoutil.GenerateKey(ctx, km, "JWT-Signer-FOO", keymanager.KeyAlgorithm_ECDSA_P256)
	s.Require().NoError(err)

	jwtSigner, err := SignJWTSignerCertificate(jwtSignerPublicKey, x509CA, x509CASigner)
	s.Require().NoError(err)

	catalog := fakeservercatalog.New()
	catalog.SetKeyManagers(km)

	s.ca = newServerCA(serverCAConfig{
		Catalog: catalog,
		TrustDomain: url.URL{
			Scheme: "spiffe",
			Host:   "example.org",
		},
		DefaultTTL: time.Minute,
	})
	s.ca.setKeypairSet(keypairSet{
		slot:      "FOO",
		x509CA:    x509CA,
		jwtSigner: jwtSigner,
	})
	s.ca.hooks.now = func() time.Time {
		return s.now
	}
}

func (s *CATestSuite) TestNoX509KeypairSet() {
	ca := newServerCA(s.ca.c)
	_, err := ca.SignX509SVID(ctx, s.generateCSR("example.org"), 0)
	s.Require().EqualError(err, "no X509-SVID keypair available")
}

func (s *CATestSuite) TestSignX509SVIDUsesDefaultTTLIfTTLUnspecified() {
	cert, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), 0)
	s.Require().NoError(err)
	s.Require().Equal(s.now.Add(-backdate), cert.NotBefore)
	s.Require().Equal(s.now.Add(time.Minute), cert.NotAfter)
}

func (s *CATestSuite) TestSignX509SVIDUsesTTLIfSpecified() {
	cert, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), time.Minute+time.Second)
	s.Require().NoError(err)
	s.Require().Equal(s.now.Add(-backdate), cert.NotBefore)
	s.Require().Equal(s.now.Add(time.Minute+time.Second), cert.NotAfter)
}

func (s *CATestSuite) TestSignX509SVIDCapsTTLToKeypairTTL() {
	cert, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), 3*time.Minute)
	s.Require().NoError(err)
	s.Require().Equal(s.now.Add(-backdate), cert.NotBefore)
	s.Require().Equal(s.now.Add(2*time.Minute), cert.NotAfter)
}

func (s *CATestSuite) TestSignX509SVIDValidatesCSR() {
	_, err := s.ca.SignX509SVID(ctx, s.generateCSR("foo.com"), 0)
	s.Require().EqualError(err, `"spiffe://foo.com" does not belong to trust domain "example.org"`)
}

func (s *CATestSuite) TestSignX509SVIDIncrementsSerialNumber() {
	cert1, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), 0)
	s.Require().NoError(err)
	s.Require().Equal(0, cert1.SerialNumber.Cmp(big.NewInt(1)))
	cert2, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), 0)
	s.Require().NoError(err)
	s.Require().Equal(0, cert2.SerialNumber.Cmp(big.NewInt(2)))
}

func (s *CATestSuite) TestNoJWTKeypairSet() {
	ca := newServerCA(s.ca.c)
	_, err := ca.SignJWTSVID(ctx, s.generateJSR("example.org"), 0)
	s.Require().EqualError(err, "no JWT-SVID keypair available")
}

func (s *CATestSuite) TestSignJWTSVIDUsesDefaultTTLIfTTLUnspecified() {
	token, err := s.ca.SignJWTSVID(ctx, s.generateJSR("example.org"), 0)
	s.Require().NoError(err)
	expiresAt, err := jwtsvid.GetTokenExpiry(token)
	s.Require().NoError(err)
	s.Require().Equal(s.now.Add(time.Minute), expiresAt)
}

func (s *CATestSuite) TestSignJWTSVIDUsesTTLIfSpecified() {
	token, err := s.ca.SignJWTSVID(ctx, s.generateJSR("example.org"), time.Minute+time.Second)
	s.Require().NoError(err)
	expiresAt, err := jwtsvid.GetTokenExpiry(token)
	s.Require().NoError(err)
	s.Require().Equal(s.now.Add(time.Minute+time.Second), expiresAt)
}

func (s *CATestSuite) TestSignJWTSVIDCapsTTLToKeypairTTL() {
	token, err := s.ca.SignJWTSVID(ctx, s.generateJSR("example.org"), 3*time.Minute)
	s.Require().NoError(err)
	expiresAt, err := jwtsvid.GetTokenExpiry(token)
	s.Require().NoError(err)
	s.Require().Equal(s.now.Add(2*time.Minute), expiresAt)
}

func (s *CATestSuite) TestSignJWTSVIDValidatesJSR() {
	// spiffe id for wrong trust domain
	_, err := s.ca.SignJWTSVID(ctx, s.generateJSR("foo.com"), 0)
	s.Require().EqualError(err, `"spiffe://foo.com/foo" does not belong to trust domain "example.org"`)

	// audience is required
	noAudience := s.generateJSR("example.org")
	noAudience.Audience = nil
	_, err = s.ca.SignJWTSVID(ctx, noAudience, 0)
	s.Require().EqualError(err, "unable to sign JWT-SVID: audience is required")
}

func (s *CATestSuite) generateCSR(trustDomain string) []byte {
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		URIs: []*url.URL{makeSpiffeID(trustDomain)},
	}, s.signer)
	s.Require().NoError(err)
	return csr
}

func (s *CATestSuite) generateJSR(trustDomain string) *node.JSR {
	workloadId := makeSpiffeID(trustDomain)
	workloadId.Path = "foo"
	return &node.JSR{
		SpiffeId: workloadId.String(),
		Audience: []string{"AUDIENCE"},
	}
}

func makeSpiffeID(trustDomain string) *url.URL {
	return &url.URL{Scheme: "spiffe", Host: trustDomain}
}
