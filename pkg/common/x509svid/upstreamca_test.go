package x509svid

import (
	"context"
	"crypto/x509"
	"net/url"
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
