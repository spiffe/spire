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
	"github.com/spiffe/spire/proto/common"
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
	x509CASigner, err := cryptoutil.GenerateKeyAndSigner(ctx, km, "x509-CA-FOO", keymanager.KeyType_EC_P256)
	s.Require().NoError(err)

	cert, err := SelfSignServerCACertificate(x509CASigner, "example.org", pkix.Name{}, s.now, s.now.Add(time.Minute*10))
	s.Require().NoError(err)

	jwtSigningKeyPKIX, err := cryptoutil.GenerateKeyRaw(ctx, km, "JWT-Signer-FOO", keymanager.KeyType_EC_P256)
	s.Require().NoError(err)

	jwtSigningKey, err := caPublicKeyFromPublicKey(&common.PublicKey{
		PkixBytes: jwtSigningKeyPKIX,
		Kid:       "foo",
		NotAfter:  cert.NotAfter.Unix(),
	})
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
		slot: "FOO",
		x509CA: &caX509CA{
			cert:  cert,
			chain: []*x509.Certificate{cert},
		},
		jwtSigningKey: jwtSigningKey,
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
	svid, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), 0)
	s.Require().NoError(err)
	s.Require().Len(svid, 1)
	s.Require().Equal(s.now.Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.now.Add(time.Minute), svid[0].NotAfter)
}

func (s *CATestSuite) TestSignX509SVIDReturnsEmptyIntermediatesIfServerCASelfSigned() {
	svid, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), 0)
	s.Require().NoError(err)
	s.Require().Len(svid, 1)
}

func (s *CATestSuite) TestSignX509SVIDReturnsIntermediatesIfNotSelfSigned() {
	intermediate := &x509.Certificate{Subject: pkix.Name{CommonName: "FAKE INTERMEDIATE"}}

	kp := s.ca.getKeypairSet()
	kp.x509CA.chain = []*x509.Certificate{intermediate, kp.x509CA.chain[0]}
	svid, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), 0)
	s.Require().NoError(err)
	s.Require().Len(svid, 2)
	s.Require().Equal(intermediate, svid[1])
}

func (s *CATestSuite) TestSignX509SVIDUsesTTLIfSpecified() {
	svid, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), time.Minute+time.Second)
	s.Require().NoError(err)
	s.Require().Len(svid, 1)
	s.Require().Equal(s.now.Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.now.Add(time.Minute+time.Second), svid[0].NotAfter)
}

func (s *CATestSuite) TestSignX509SVIDCapsTTLToKeypairTTL() {
	svid, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), time.Hour)
	s.Require().NoError(err)
	s.Require().Len(svid, 1)
	s.Require().Equal(s.now.Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.now.Add(10*time.Minute), svid[0].NotAfter)
}

func (s *CATestSuite) TestSignX509SVIDValidatesCSR() {
	_, err := s.ca.SignX509SVID(ctx, s.generateCSR("foo.com"), 0)
	s.Require().EqualError(err, `"spiffe://foo.com" does not belong to trust domain "example.org"`)
}

func (s *CATestSuite) TestSignX509SVIDIncrementsSerialNumber() {
	svid1, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), 0)
	s.Require().NoError(err)
	s.Require().Len(svid1, 1)
	s.Require().Equal(0, svid1[0].SerialNumber.Cmp(big.NewInt(1)))
	svid2, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), 0)
	s.Require().NoError(err)
	s.Require().Len(svid2, 1)
	s.Require().Equal(0, svid2[0].SerialNumber.Cmp(big.NewInt(2)))
}

func (s *CATestSuite) TestNoJWTKeypairSet() {
	ca := newServerCA(s.ca.c)
	_, err := ca.SignJWTSVID(ctx, s.generateJSR("example.org", 0))
	s.Require().EqualError(err, "no JWT-SVID keypair available")
}

func (s *CATestSuite) TestSignJWTSVIDUsesDefaultTTLIfTTLUnspecified() {
	token, err := s.ca.SignJWTSVID(ctx, s.generateJSR("example.org", 0))
	s.Require().NoError(err)
	issuedAt, expiresAt, err := jwtsvid.GetTokenExpiry(token)
	s.Require().NoError(err)
	s.Require().Equal(s.now, issuedAt)
	s.Require().Equal(s.now.Add(DefaultJWTSVIDTTL), expiresAt)
}

func (s *CATestSuite) TestSignJWTSVIDUsesTTLIfSpecified() {
	token, err := s.ca.SignJWTSVID(ctx, s.generateJSR("example.org", time.Minute+time.Second))
	s.Require().NoError(err)
	issuedAt, expiresAt, err := jwtsvid.GetTokenExpiry(token)
	s.Require().NoError(err)
	s.Require().Equal(s.now, issuedAt)
	s.Require().Equal(s.now.Add(time.Minute+time.Second), expiresAt)
}

func (s *CATestSuite) TestSignJWTSVIDCapsTTLToKeypairTTL() {
	token, err := s.ca.SignJWTSVID(ctx, s.generateJSR("example.org", time.Hour))
	s.Require().NoError(err)
	issuedAt, expiresAt, err := jwtsvid.GetTokenExpiry(token)
	s.Require().NoError(err)
	s.Require().Equal(s.now, issuedAt)
	s.Require().Equal(s.now.Add(10*time.Minute), expiresAt)
}

func (s *CATestSuite) TestSignJWTSVIDValidatesJSR() {
	// spiffe id for wrong trust domain
	_, err := s.ca.SignJWTSVID(ctx, s.generateJSR("foo.com", 0))
	s.Require().EqualError(err, `"spiffe://foo.com/foo" does not belong to trust domain "example.org"`)

	// audience is required
	noAudience := s.generateJSR("example.org", 0)
	noAudience.Audience = nil
	_, err = s.ca.SignJWTSVID(ctx, noAudience)
	s.Require().EqualError(err, "unable to sign JWT-SVID: audience is required")
}

func (s *CATestSuite) generateCSR(trustDomain string) []byte {
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		URIs: []*url.URL{makeSpiffeID(trustDomain)},
	}, s.signer)
	s.Require().NoError(err)
	return csr
}

func (s *CATestSuite) generateJSR(trustDomain string, ttl time.Duration) *node.JSR {
	workloadId := makeSpiffeID(trustDomain)
	workloadId.Path = "foo"
	return &node.JSR{
		SpiffeId: workloadId.String(),
		Audience: []string{"AUDIENCE"},
		Ttl:      int32(ttl / time.Second),
	}
}

func makeSpiffeID(trustDomain string) *url.URL {
	return &url.URL{Scheme: "spiffe", Host: trustDomain}
}
