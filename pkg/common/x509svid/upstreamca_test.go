package x509svid

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/test/clock"
	"github.com/stretchr/testify/suite"
)

func TestUpstreamCA(t *testing.T) {
	suite.Run(t, new(UpstreamCASuite))
}

type UpstreamCASuite struct {
	caSuite

	clock      *clock.Mock
	upstreamCA *UpstreamCA
}

func (s *UpstreamCASuite) SetupTest() {
	s.clock = clock.NewMock(s.T())
	s.caSuite.SetupTest()
	s.configure()
}

func (s *UpstreamCASuite) configure() {
	s.upstreamCA = NewUpstreamCA(s.keypair, spiffeid.RequireTrustDomainFromString("example.org"), UpstreamCAOptions{
		Clock: s.clock,
	})
}

func (s *UpstreamCASuite) TestSignCSRWithInvalidCSR() {
	cert, err := s.upstreamCA.SignCSR(context.Background(), nil, 0)
	s.requireErrorContains(err, "unable to parse CSR")
	s.Require().Nil(cert)
}

func (s *UpstreamCASuite) TestSignCSRWithBadCSRSignature() {
	csr := s.makeCSR("spiffe://example.org")
	csr[len(csr)-1]++
	cert, err := s.upstreamCA.SignCSR(context.Background(), csr, 0)
	s.requireErrorContains(err, "CSR signature check failed")
	s.Require().Nil(cert)
}

func (s *UpstreamCASuite) TestSignCSRWithNoURISAN() {
	csr := s.makeCSR("")
	cert, err := s.upstreamCA.SignCSR(context.Background(), csr, 0)
	s.requireErrorContains(err, "CSR must have exactly one URI SAN")
	s.Require().Nil(cert)
}

func (s *UpstreamCASuite) TestSignCSRWithWrongTrustDomain() {
	csr := s.makeCSR("spiffe://domain.test")
	cert, err := s.upstreamCA.SignCSR(context.Background(), csr, 0)
	s.requireErrorContains(err, `CSR with SPIFFE ID "spiffe://domain.test" is invalid: must use the trust domain ID for trust domain "example.org"`)
	s.Require().Nil(cert)
}

func (s *UpstreamCASuite) TestSignCSRWithWorkloadID() {
	// spiffe ID for workload
	csr := s.makeCSR("spiffe://example.org/foo")
	cert, err := s.upstreamCA.SignCSR(context.Background(), csr, 0)
	s.requireErrorContains(err, `CSR with SPIFFE ID "spiffe://example.org/foo" is invalid: must use the trust domain ID for trust domain "example.org"`)
	s.Require().Nil(cert)
}

func (s *UpstreamCASuite) TestSignCSRSuccess() {
	csr := s.makeCSR("spiffe://example.org")
	cert, err := s.upstreamCA.SignCSR(context.Background(), csr, 0)
	s.Require().NoError(err)

	s.Require().EqualValues(cert.URIs, []*url.URL{
		{Scheme: "spiffe", Host: "example.org"},
	})
	s.Require().True(cert.IsCA)
	s.Require().Equal("COMMONNAME", cert.Subject.CommonName)
	s.Require().NotEmpty(cert.SubjectKeyId)
	s.Require().Equal(x509.KeyUsageCertSign|
		x509.KeyUsageCRLSign, cert.KeyUsage)
}

func (s *UpstreamCASuite) TestSignCSRKeepsRDNorder() {
	u, err := url.Parse("spiffe://example.org")
	s.Require().NoError(err)

	// Note! don't use pkix.Name its serialization is wrong!
	// Using ExtraNames preserves RDNs order and does not make them multi-valued
	var (
		asn1Country            = []int{2, 5, 4, 6}
		asn1Organization       = []int{2, 5, 4, 10}
		asn1OrganizationalUnit = []int{2, 5, 4, 11}
		asn1CommonName         = []int{2, 5, 4, 3}
	)

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1Country, Value: "US"},
				{Type: asn1Organization, Value: "SPIRE"},
				{Type: asn1OrganizationalUnit, Value: "ABC Unit"},
				{Type: asn1OrganizationalUnit, Value: "DEF:Department"},
				{Type: asn1OrganizationalUnit, Value: "example.com"},
				{Type: asn1CommonName, Value: "COMMONNAME"},
			},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		URIs:               []*url.URL{u},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, s.csrKey)
	s.Require().NoError(err)

	cert, err := s.upstreamCA.SignCSR(context.Background(), csr, 0)
	s.Require().NoError(err)

	var subject pkix.RDNSequence
	_, err = asn1.Unmarshal(cert.RawSubject, &subject)
	s.Require().NoError(err)

	// A multi-value RDN is something different than multiple RDNs of same OID:
	// OU=A + OU=B - order is undefined
	// OU=A, OU=B - order is defined
	// if using pkix.Name result will be 4 RDNs with multi-value OU
	rdns := strings.Split(subject.String(), ",")
	s.Require().Len(rdns, 6, "Subject RDN should have 6 parts (C,O,3OU,CN)")

	// RDNs are in reverse order
	s.Assert().Equal("C=US", rdns[5])
	s.Assert().Equal("O=SPIRE", rdns[4])
	s.Assert().Equal("OU=ABC Unit", rdns[3])
	s.Assert().Equal("OU=DEF:Department", rdns[2])
	s.Assert().Equal("OU=example.com", rdns[1])
	s.Assert().Equal("CN=COMMONNAME", rdns[0])
}

func (s *UpstreamCASuite) TestSignCSRExtensionIsCopied() {
	u, err := url.Parse("spiffe://example.org")
	s.Require().NoError(err)

	var (
		dummyExtension = pkix.Extension{
			Id:       []int{1, 2, 3, 4},
			Critical: true,
			Value:    []byte("extra extension"),
		}
	)

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "COMMONNAME",
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		URIs:               []*url.URL{u},
		ExtraExtensions:    []pkix.Extension{dummyExtension},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, s.csrKey)
	s.Require().NoError(err)

	cert, err := s.upstreamCA.SignCSR(context.Background(), csr, 0)
	s.Require().NoError(err)

	s.Require().Contains(cert.Extensions, dummyExtension)
}

func (s *UpstreamCASuite) TestSignCSRCapsNotAfter() {
	csr := s.makeCSR("spiffe://example.org")
	cert, err := s.upstreamCA.SignCSR(context.Background(), csr, 3*time.Hour)
	s.Require().NoError(err)

	s.Require().Equal(s.caCert.NotAfter, cert.NotAfter)
}

func (s *UpstreamCASuite) TestSignCSRUsesPreferredTTLIfSet() {
	csr := s.makeCSR("spiffe://example.org")
	cert, err := s.upstreamCA.SignCSR(context.Background(), csr, time.Minute)
	s.Require().NoError(err)

	s.Require().Equal(s.clock.Now().Add(time.Minute).UTC(), cert.NotAfter)
}

func (s *UpstreamCASuite) TestSignCSRUsesDefaultTTLIfPreferredTTLUnset() {
	csr := s.makeCSR("spiffe://example.org")
	cert, err := s.upstreamCA.SignCSR(context.Background(), csr, 0)
	s.Require().NoError(err)

	s.Require().Equal(s.clock.Now().Add(DefaultUpstreamCATTL).UTC(), cert.NotAfter)
}
