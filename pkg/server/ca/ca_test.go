package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/api/node"
	"github.com/spiffe/spire/test/clock"
	"github.com/stretchr/testify/suite"
)

var (
	testSigner, _ = pemutil.ParseSigner([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgt/OIyb8Ossz/5bNk
XtnzFe1T2d0D9quX9Loi1O55b8yhRANCAATDe/2d6z+P095I3dIkocKr4b3zAy+1
qQDuoXqa8i3YOPk5fLib4ORzqD9NJFcrKjI+LLtipQe9yu/eY1K0yhBa
-----END PRIVATE KEY-----
`))

	ctx = context.Background()
)

func TestCA(t *testing.T) {
	suite.Run(t, new(CATestSuite))
}

type CATestSuite struct {
	suite.Suite

	logHook      *test.Hook
	clock        *clock.Mock
	upstreamCert *x509.Certificate
	caCert       *x509.Certificate

	ca *CA
}

func (s *CATestSuite) SetupSuite() {
	s.clock = clock.NewMock(s.T())
	s.clock.Set(time.Now().Truncate(time.Second).UTC())

	s.upstreamCert = s.createCACertificate("UPSTREAMCA", nil)
	s.caCert = s.createCACertificate("CA", s.upstreamCert)
}

func (s *CATestSuite) SetupTest() {
	log, logHook := test.NewNullLogger()
	s.logHook = logHook

	s.ca = NewCA(CAConfig{
		Log:     log,
		Metrics: telemetry.Blackhole{},
		TrustDomain: url.URL{
			Scheme: "spiffe",
			Host:   "example.org",
		},
		X509SVIDTTL: time.Minute,
		Clock:       s.clock,
		CASubject: pkix.Name{
			CommonName: "TESTCA",
		},
	})
	s.setX509CA(false)
	s.setJWTKey()
}

func (s *CATestSuite) TestNoX509CASet() {
	s.ca.SetX509CA(nil)
	_, err := s.ca.SignX509CASVID(ctx, s.generateCSR(), X509Params{})
	s.Require().EqualError(err, "X509 CA is not available for signing")
}

func (s *CATestSuite) TestSignServerX509SVID() {
	svidChain, err := s.ca.SignServerX509SVID(ctx, s.generateCSR(), X509Params{})
	s.Require().NoError(err)
	s.Require().Len(svidChain, 2)

	s.Equal(s.ca.x509CA.Certificate, svidChain[1])
}

func (s *CATestSuite) TestSignX509SVID() {
	svidChain, err := s.ca.SignX509SVID(ctx, s.generateCSR(), X509Params{})
	s.Require().NoError(err)
	s.Require().Len(svidChain, 1)

	svid := svidChain[0]

	s.False(svid.NotBefore.IsZero(), "NotBefore is not set")
	s.False(svid.NotAfter.IsZero(), "NotAfter is not set")
	s.NotEmpty(svid.SubjectKeyId, "SubjectKeyId is not set")
	s.NotEmpty(svid.AuthorityKeyId, "AuthorityKeyId is not set")
	s.Equal(x509.KeyUsageKeyEncipherment|x509.KeyUsageKeyAgreement|x509.KeyUsageDigitalSignature, svid.KeyUsage, "key usage does not match")
	s.Equal([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, svid.ExtKeyUsage, "ext key usage does not match")
	s.False(svid.IsCA, "CA bit is set")
	s.True(svid.BasicConstraintsValid, "Basic constraints are not valid")

	// SPIFFE ID should be set to that of the trust domain
	if s.Len(svid.URIs, 1, "has no URIs") {
		s.Equal("spiffe://example.org/workload", svid.URIs[0].String())
	}

	// Subject is hard coded by the CA and should not be pulled from the CSR.
	s.Equal("O=SPIRE,C=US", svid.Subject.String())
}

func (s *CATestSuite) TestSignX509SVIDCannotSignTrustDomainID() {
	csr := s.createCSR(&x509.CertificateRequest{
		URIs: []*url.URL{makeTrustDomainID("example.org")},
	})
	_, err := s.ca.SignX509SVID(ctx, csr, X509Params{})
	s.Require().EqualError(err, `"spiffe://example.org" is not a valid trust domain member SPIFFE ID: path is empty`)
}

func (s *CATestSuite) TestSignX509SVIDUsesDefaultTTLIfTTLUnspecified() {
	svid, err := s.ca.SignX509SVID(ctx, s.generateCSR(), X509Params{})
	s.Require().NoError(err)
	s.Require().Len(svid, 1)
	s.Require().Equal(s.clock.Now().Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.clock.Now().Add(time.Minute), svid[0].NotAfter)
}

func (s *CATestSuite) TestSignX509SVIDUsesDefaultTTLAndNoCNDNS() {
	svid, err := s.ca.SignX509SVID(ctx, s.generateCSR(), X509Params{})
	s.Require().NoError(err)
	s.Require().Len(svid, 1)
	s.Require().Equal(s.clock.Now().Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.clock.Now().Add(time.Minute), svid[0].NotAfter)
	s.Require().Empty(svid[0].DNSNames)
	s.Require().Empty(svid[0].Subject.CommonName)
}

func (s *CATestSuite) TestSignX509SVIDSingleDNS() {
	dnsList := []string{"somehost1"}
	svid, err := s.ca.SignX509SVID(ctx, s.generateCSR(), X509Params{DNSList: dnsList})
	s.Require().NoError(err)
	s.Require().Len(svid, 1)
	s.Require().Equal(s.clock.Now().Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.clock.Now().Add(time.Minute), svid[0].NotAfter)
	s.Require().Equal(dnsList, svid[0].DNSNames)
	s.Require().Equal("somehost1", svid[0].Subject.CommonName)
}

func (s *CATestSuite) TestSignX509SVIDMultipleDNS() {
	dnsList := []string{"somehost1", "somehost2", "somehost3"}
	svid, err := s.ca.SignX509SVID(ctx, s.generateCSR(), X509Params{DNSList: dnsList})
	s.Require().NoError(err)
	s.Require().Len(svid, 1)
	s.Require().Equal(s.clock.Now().Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.clock.Now().Add(time.Minute), svid[0].NotAfter)
	s.Require().Equal(dnsList, svid[0].DNSNames)
	s.Require().Equal("somehost1", svid[0].Subject.CommonName)
}

func (s *CATestSuite) TestSignX509SVIDReturnsChainIfIntermediate() {
	s.setX509CA(true)
	svid, err := s.ca.SignX509SVID(ctx, s.generateCSR(), X509Params{})
	s.Require().NoError(err)
	s.Require().Len(svid, 3)
	s.Require().NotNil(svid[0])
	s.Require().Equal(s.caCert, svid[1])
	s.Require().Equal(s.upstreamCert, svid[2])
}

func (s *CATestSuite) TestSignX509SVIDUsesTTLIfSpecified() {
	svid, err := s.ca.SignX509SVID(ctx, s.generateCSR(), X509Params{TTL: time.Minute + time.Second})
	s.Require().NoError(err)
	s.Require().Len(svid, 1)
	s.Require().Equal(s.clock.Now().Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.clock.Now().Add(time.Minute+time.Second), svid[0].NotAfter)
}

func (s *CATestSuite) TestSignX509SVIDCapsTTLToCATTL() {
	svid, err := s.ca.SignX509SVID(ctx, s.generateCSR(), X509Params{TTL: time.Hour})
	s.Require().NoError(err)
	s.Require().Len(svid, 1)
	s.Require().Equal(s.clock.Now().Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.clock.Now().Add(10*time.Minute), svid[0].NotAfter)
}

func (s *CATestSuite) TestSignX509SVIDValidatesTrustDomain() {
	_, err := s.ca.SignX509SVID(ctx, s.generateCSRInDomain("foo.com"), X509Params{})
	s.Require().EqualError(err, `"spiffe://foo.com/workload" does not belong to trust domain "example.org"`)
}

func (s *CATestSuite) TestSignX509SVIDWithEvilSubject() {
	csr := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "mybank.example.org",
		},
		URIs: []*url.URL{makeWorkloadID("example.org")},
	}
	certs, err := s.ca.SignX509SVID(ctx, s.createCSR(csr), X509Params{})
	s.Require().NoError(err)
	s.Assert().NotEqual("mybank.example.org", certs[0].Subject.CommonName)
}

func (s *CATestSuite) TestSignX509SVIDIncrementsSerialNumber() {
	svid1, err := s.ca.SignX509SVID(ctx, s.generateCSR(), X509Params{})
	s.Require().NoError(err)
	s.Require().Len(svid1, 1)
	s.Require().Equal(0, svid1[0].SerialNumber.Cmp(big.NewInt(1)))
	svid2, err := s.ca.SignX509SVID(ctx, s.generateCSR(), X509Params{})
	s.Require().NoError(err)
	s.Require().Len(svid2, 1)
	s.Require().Equal(0, svid2[0].SerialNumber.Cmp(big.NewInt(2)))
}

func (s *CATestSuite) TestNoJWTKeySet() {
	s.ca.SetJWTKey(nil)
	_, err := s.ca.SignJWTSVID(ctx, s.generateJSR("example.org", 0))
	s.Require().EqualError(err, "JWT key is not available for signing")
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

func (s *CATestSuite) TestSignJWTSVIDCapsTTLToKeyExpiry() {
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
	s.Require().EqualError(err, "unable to sign JWT SVID: audience is required")
}

func (s *CATestSuite) TestSignX509CASVID() {
	svidChain, err := s.ca.SignX509CASVID(ctx, s.generateCACSR("example.org"), X509Params{})
	s.Require().NoError(err)
	s.Require().Len(svidChain, 1)

	svid := svidChain[0]

	s.False(svid.NotBefore.IsZero(), "NotBefore is not set")
	s.False(svid.NotAfter.IsZero(), "NotAfter is not set")
	s.NotEmpty(svid.SubjectKeyId, "SubjectKeyId is not set")
	s.NotEmpty(svid.AuthorityKeyId, "AuthorityKeyId is not set")
	s.Equal(x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign, svid.KeyUsage, "key usage does not match")
	s.True(svid.IsCA, "CA bit is not set")
	s.True(svid.BasicConstraintsValid, "Basic constraints are not valid")

	// SPIFFE ID should be set to that of the trust domain
	if s.Len(svid.URIs, 1, "has no URIs") {
		s.Equal("spiffe://example.org", svid.URIs[0].String())
	}

	// Subject is controlled exclusively by the CA and should not be pulled from
	// the CSR. The DOWNSTREAM OU should be appended.
	s.Equal("CN=CA,OU=DOWNSTREAM-1", svid.Subject.String())
}

func (s *CATestSuite) TestSignX509CASVIDUsesDefaultTTLIfTTLUnspecified() {
	svid, err := s.ca.SignX509CASVID(ctx, s.generateCACSR("example.org"), X509Params{})
	s.Require().NoError(err)
	s.Require().Len(svid, 1)
	s.Require().Equal(s.clock.Now().Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.clock.Now().Add(time.Minute), svid[0].NotAfter)
}

func (s *CATestSuite) TestSignCAX509SVIDValidatesTrustDomain() {
	_, err := s.ca.SignX509SVID(ctx, s.generateCACSR("foo.com"), X509Params{})
	s.Require().EqualError(err, `"spiffe://foo.com" does not belong to trust domain "example.org"`)
}

func (s *CATestSuite) setX509CA(upstreamBundle bool) {
	var upstreamChain []*x509.Certificate
	if upstreamBundle {
		upstreamChain = []*x509.Certificate{s.caCert, s.upstreamCert}
	}
	s.ca.SetX509CA(&X509CA{
		Signer:        testSigner,
		Certificate:   s.caCert,
		UpstreamChain: upstreamChain,
	})
}

func (s *CATestSuite) setJWTKey() {
	s.ca.SetJWTKey(&JWTKey{
		Signer:   testSigner,
		Kid:      "KID",
		NotAfter: s.clock.Now().Add(10 * time.Minute),
	})
}

func (s *CATestSuite) generateCSR() []byte {
	return s.generateCSRInDomain("example.org")
}

func (s *CATestSuite) generateCSRInDomain(trustDomain string) []byte {
	return s.createCSR(&x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"IGNORE ME"},
			Organization: []string{"IGNORE ME"},
		},
		URIs: []*url.URL{makeWorkloadID(trustDomain)},
	})
}

func (s *CATestSuite) generateCACSR(trustDomain string) []byte {
	return s.createCSR(&x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"IGNORE ME"},
			Organization: []string{"IGNORE ME"},
		},
		URIs: []*url.URL{makeTrustDomainID(trustDomain)},
	})
}

func (s *CATestSuite) createCSR(csr *x509.CertificateRequest) []byte {
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, testSigner)
	s.Require().NoError(err)
	return csrBytes
}

func (s *CATestSuite) generateJSR(trustDomain string, ttl time.Duration) *node.JSR {
	workloadId := makeWorkloadID(trustDomain)
	workloadId.Path = "foo"
	return &node.JSR{
		SpiffeId: workloadId.String(),
		Audience: []string{"AUDIENCE"},
		Ttl:      int32(ttl / time.Second),
	}
}

func (s *CATestSuite) createCACertificate(cn string, parent *x509.Certificate) *x509.Certificate {
	keyID, err := x509util.GetSubjectKeyId(testSigner.Public())
	s.Require().NoError(err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName: cn,
		},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotAfter:              s.clock.Now().Add(10 * time.Minute),
		SubjectKeyId:          keyID,
	}
	if parent == nil {
		parent = template
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, testSigner.Public(), testSigner)
	s.Require().NoError(err)
	cert, err := x509.ParseCertificate(certDER)
	s.Require().NoError(err)
	return cert
}

func makeWorkloadID(trustDomain string) *url.URL {
	return &url.URL{Scheme: "spiffe", Host: trustDomain, Path: "/workload"}
}

func makeTrustDomainID(trustDomain string) *url.URL {
	return &url.URL{Scheme: "spiffe", Host: trustDomain}
}
