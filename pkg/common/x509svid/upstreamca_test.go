package x509svid

import (
	"context"
	"crypto/x509"
	"net/url"
	"testing"
	"time"

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
	s.configure(time.Hour)
}

func (s *UpstreamCASuite) configure(ttl time.Duration) {
	s.upstreamCA = NewUpstreamCA(s.keypair, "example.org", UpstreamCAOptions{
		TTL:   ttl,
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
	csr := s.makeCSR("spiffe://eggs-ample.org")
	cert, err := s.upstreamCA.SignCSR(context.Background(), csr, 0)
	s.requireErrorContains(err, `"spiffe://eggs-ample.org" does not belong to trust domain`)
	s.Require().Nil(cert)
}

func (s *UpstreamCASuite) TestSignCSRWithWorkloadID() {
	// spiffe ID for workload
	csr := s.makeCSR("spiffe://example.org/foo")
	cert, err := s.upstreamCA.SignCSR(context.Background(), csr, 0)
	s.requireErrorContains(err, `"spiffe://example.org/foo" is not a valid trust domain SPIFFE ID`)
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
	s.Require().Equal(x509.KeyUsageDigitalSignature|
		x509.KeyUsageCertSign|
		x509.KeyUsageCRLSign, cert.KeyUsage)
}

func (s *UpstreamCASuite) TestSignCSRCapsNotAfter() {
	s.configure(3 * time.Hour)

	csr := s.makeCSR("spiffe://example.org")
	cert, err := s.upstreamCA.SignCSR(context.Background(), csr, 0)
	s.Require().NoError(err)

	s.Require().Equal(s.caCert.NotAfter, cert.NotAfter)
}

func (s *UpstreamCASuite) TestSignCSRUsesPreferredTTLIfOptionsTTLUnset() {
	s.configure(0)

	csr := s.makeCSR("spiffe://example.org")
	cert, err := s.upstreamCA.SignCSR(context.Background(), csr, time.Minute)
	s.Require().NoError(err)

	s.Require().Equal(s.clock.Now().Add(time.Minute).UTC(), cert.NotAfter)
}

func (s *UpstreamCASuite) TestSignCSRUsesOptionsTTLOverPreferredTTL() {
	s.configure(time.Minute * 2)

	csr := s.makeCSR("spiffe://example.org")
	cert, err := s.upstreamCA.SignCSR(context.Background(), csr, time.Minute)
	s.Require().NoError(err)

	s.Require().Equal(s.clock.Now().Add(2*time.Minute).UTC(), cert.NotAfter)
}

func (s *UpstreamCASuite) TestSignCSRUsesDefaultTTLIfOptionsAndPreferredTTLUnset() {
	s.configure(0)

	csr := s.makeCSR("spiffe://example.org")
	cert, err := s.upstreamCA.SignCSR(context.Background(), csr, 0)
	s.Require().NoError(err)

	s.Require().Equal(s.clock.Now().Add(DefaultUpstreamCATTL).UTC(), cert.NotAfter)
}
