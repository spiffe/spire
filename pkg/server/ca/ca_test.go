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
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/memory"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/keymanager"
	"github.com/spiffe/spire/test/clock"
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
	clock  *clock.Mock
	ca     *serverCA
}

func (s *CATestSuite) SetupTest() {
	key, err := pemutil.ParseECPrivateKey(keyPEM)
	s.Require().NoError(err)
	s.signer = key
	s.clock = clock.NewMock(s.T())
	s.clock.Set(time.Now().Truncate(time.Second).UTC())

	km := memory.New()
	x509CASigner, err := cryptoutil.GenerateKeyAndSigner(ctx, km, "x509-CA-FOO", keymanager.KeyType_EC_P256)
	s.Require().NoError(err)

	cert, err := SelfSignServerCACertificate(x509CASigner, "example.org", pkix.Name{}, s.clock.Now(), s.clock.Now().Add(time.Minute*10))
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
	catalog.SetKeyManager(km)

	logger, err := log.NewLogger("DEBUG", "")
	s.Require().NoError(err)

	s.ca = newServerCA(serverCAConfig{
		Log:     logger,
		Metrics: telemetry.Blackhole{},
		Catalog: catalog,
		TrustDomain: url.URL{
			Scheme: "spiffe",
			Host:   "example.org",
		},
		DefaultTTL: time.Minute,
		CASubject: pkix.Name{
			Country:      []string{"TEST"},
			Organization: []string{"TEST"},
		},
		Clock: s.clock,
	})
	s.ca.setKeypairSet(keypairSet{
		slot: "FOO",
		x509CA: &caX509CA{
			chain: []*x509.Certificate{cert},
		},
		jwtSigningKey: jwtSigningKey,
	})
}

func (s *CATestSuite) TestNoX509KeypairSet() {
	ca := newServerCA(s.ca.c)
	_, err := ca.SignX509SVID(ctx, s.generateCSR("example.org"), X509Params{})
	s.Require().EqualError(err, "no X509-SVID keypair available")
}

func (s *CATestSuite) TestSignX509SVIDUsesDefaultTTLIfTTLUnspecified() {
	svid, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), X509Params{})
	s.Require().NoError(err)
	s.Require().Len(svid, 2)
	s.Require().Equal(s.clock.Now().Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.clock.Now().Add(time.Minute), svid[0].NotAfter)
}

func (s *CATestSuite) TestSignX509SVIDUsesDefaultTTLAndNoCNDNS() {
	svid, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), X509Params{})
	s.Require().NoError(err)
	s.Require().Len(svid, 2)
	s.Require().Equal(s.clock.Now().Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.clock.Now().Add(time.Minute), svid[0].NotAfter)
	s.Require().Empty(svid[0].DNSNames)
	s.Require().Empty(svid[0].Subject.CommonName)
}

func (s *CATestSuite) TestSignX509SVIDSingleDNS() {
	dnsList := []string{"somehost1"}
	svid, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), X509Params{DNSList: dnsList})
	s.Require().NoError(err)
	s.Require().Len(svid, 2)
	s.Require().Equal(s.clock.Now().Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.clock.Now().Add(time.Minute), svid[0].NotAfter)
	s.Require().Equal(dnsList, svid[0].DNSNames)
	s.Require().Equal("somehost1", svid[0].Subject.CommonName)
}

func (s *CATestSuite) TestSignX509SVIDMultipleDNS() {
	dnsList := []string{"somehost1", "somehost2", "somehost3"}
	svid, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), X509Params{DNSList: dnsList})
	s.Require().NoError(err)
	s.Require().Len(svid, 2)
	s.Require().Equal(s.clock.Now().Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.clock.Now().Add(time.Minute), svid[0].NotAfter)
	s.Require().Equal(dnsList, svid[0].DNSNames)
	s.Require().Equal("somehost1", svid[0].Subject.CommonName)
}

func (s *CATestSuite) TestSignX509SVIDReturnsEmptyIntermediatesIfServerCASelfSigned() {
	svid, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), X509Params{})
	s.Require().NoError(err)
	s.Require().Len(svid, 2)
}

func (s *CATestSuite) TestSignX509SVIDReturnsIntermediatesIfNotSelfSigned() {
	intermediate := &x509.Certificate{Subject: pkix.Name{CommonName: "FAKE INTERMEDIATE"}}

	kp := s.ca.getKeypairSet()
	kp.x509CA.chain = []*x509.Certificate{intermediate, kp.x509CA.chain[0]}
	svid, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), X509Params{})
	s.Require().NoError(err)
	s.Require().Len(svid, 3)
	s.Require().Equal(intermediate, svid[1])
}

func (s *CATestSuite) TestSignX509SVIDUsesTTLIfSpecified() {
	svid, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), X509Params{TTL: time.Minute + time.Second})
	s.Require().NoError(err)
	s.Require().Len(svid, 2)
	s.Require().Equal(s.clock.Now().Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.clock.Now().Add(time.Minute+time.Second), svid[0].NotAfter)
}

func (s *CATestSuite) TestSignX509SVIDCapsTTLToKeypairTTL() {
	svid, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), X509Params{TTL: time.Hour})
	s.Require().NoError(err)
	s.Require().Len(svid, 2)
	s.Require().Equal(s.clock.Now().Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.clock.Now().Add(10*time.Minute), svid[0].NotAfter)
}

func (s *CATestSuite) TestSignX509SVIDValidatesCSR() {
	_, err := s.ca.SignX509SVID(ctx, s.generateCSR("foo.com"), X509Params{})
	s.Require().EqualError(err, `"spiffe://foo.com" does not belong to trust domain "example.org"`)
}

func (s *CATestSuite) TestSignX509SVIDWithEvilSubject() {
	csr := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "mybank.example.org",
		},
		URIs: []*url.URL{makeSpiffeID("example.org")},
	}
	certs, err := s.ca.SignX509SVID(ctx, s.signCSR(csr), X509Params{})
	s.Require().NoError(err)
	s.Assert().NotEqual("mybank.example.org", certs[0].Subject.CommonName)
}

func (s *CATestSuite) TestSignX509SVIDIncrementsSerialNumber() {
	svid1, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), X509Params{})
	s.Require().NoError(err)
	s.Require().Len(svid1, 2)
	s.Require().Equal(0, svid1[0].SerialNumber.Cmp(big.NewInt(1)))
	svid2, err := s.ca.SignX509SVID(ctx, s.generateCSR("example.org"), X509Params{})
	s.Require().NoError(err)
	s.Require().Len(svid2, 2)
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
	s.Require().Equal(s.clock.Now(), issuedAt)
	s.Require().Equal(s.clock.Now().Add(DefaultJWTSVIDTTL), expiresAt)
}

func (s *CATestSuite) TestSignJWTSVIDUsesTTLIfSpecified() {
	token, err := s.ca.SignJWTSVID(ctx, s.generateJSR("example.org", time.Minute+time.Second))
	s.Require().NoError(err)
	issuedAt, expiresAt, err := jwtsvid.GetTokenExpiry(token)
	s.Require().NoError(err)
	s.Require().Equal(s.clock.Now(), issuedAt)
	s.Require().Equal(s.clock.Now().Add(time.Minute+time.Second), expiresAt)
}

func (s *CATestSuite) TestSignJWTSVIDCapsTTLToKeypairTTL() {
	token, err := s.ca.SignJWTSVID(ctx, s.generateJSR("example.org", time.Hour))
	s.Require().NoError(err)
	issuedAt, expiresAt, err := jwtsvid.GetTokenExpiry(token)
	s.Require().NoError(err)
	s.Require().Equal(s.clock.Now(), issuedAt)
	s.Require().Equal(s.clock.Now().Add(10*time.Minute), expiresAt)
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

func (s *CATestSuite) TestNoX509KeypairSetCASVID() {
	ca := newServerCA(s.ca.c)
	_, err := ca.SignX509CASVID(ctx, s.generateCSR("example.org"), X509Params{})
	s.Require().EqualError(err, "no X509-SVID keypair available")
}

func (s *CATestSuite) TestSignX509CASVIDUsesDefaultTTLIfTTLUnspecified() {
	svid, err := s.ca.SignX509CASVID(ctx, s.generateCSR("example.org"), X509Params{})
	s.Require().NoError(err)
	s.Require().Len(svid, 2)
	s.Require().Equal(s.clock.Now().Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.clock.Now().Add(time.Minute), svid[0].NotAfter)
}

func (s *CATestSuite) TestSignX509CASVIDWithDifferentSubject() {
	subject := pkix.Name{
		Country:      []string{"INVALID"},
		Organization: []string{"INVALID"},
	}
	svid, err := s.ca.SignX509CASVID(ctx, s.generateCSRWithSubject("example.org", subject), X509Params{})
	s.Require().NoError(err)
	s.Require().Len(svid, 2)
	s.Require().Equal(svid[0].Subject.Country[0], "TEST")
	s.Require().Equal(svid[0].Subject.Organization[0], "TEST")
}

func (s *CATestSuite) generateCSR(trustDomain string) []byte {
	csr := &x509.CertificateRequest{
		URIs: []*url.URL{makeSpiffeID(trustDomain)},
	}
	return s.signCSR(csr)
}

func (s *CATestSuite) signCSR(csr *x509.CertificateRequest) []byte {
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, s.signer)
	s.Require().NoError(err)
	return csrBytes
}

func (s *CATestSuite) generateCSRWithSubject(trustDomain string, subject pkix.Name) []byte {
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: subject,
		URIs:    []*url.URL{makeSpiffeID(trustDomain)},
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
