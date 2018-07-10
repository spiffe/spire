package x509svid

import (
	"context"
	"crypto/x509"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

func TestServerCA(t *testing.T) {
	suite.Run(t, new(ServerCASuite))
}

type ServerCASuite struct {
	caSuite

	serverCA *ServerCA
}

func (s *ServerCASuite) SetupTest() {
	s.caSuite.SetupTest()
	s.serverCA = NewServerCA(s.keypair, "example.org", ServerCAOptions{
		TTL: time.Hour,
	})
}

func (s *ServerCASuite) TestSignCSRWithInvalidCSR() {
	cert, err := s.serverCA.SignCSR(context.Background(), nil, 0)
	s.requireErrorContains(err, "unable to parse CSR")
	s.Require().Nil(cert)
}

func (s *ServerCASuite) TestSignCSRWithBadCSRSignature() {
	csr := s.makeCSR("spiffe://example.org")
	csr[len(csr)-1] ^= csr[len(csr)-1]
	cert, err := s.serverCA.SignCSR(context.Background(), csr, 0)
	s.requireErrorContains(err, "CSR signature check failed")
	s.Require().Nil(cert)
}

func (s *ServerCASuite) TestSignCSRWithNoURISAN() {
	csr := s.makeCSR("")
	cert, err := s.serverCA.SignCSR(context.Background(), csr, 0)
	s.requireErrorContains(err, "CSR must have exactly one URI SAN")
	s.Require().Nil(cert)
}

func (s *ServerCASuite) TestSignCSRWithWrongTrustDomain() {
	csr := s.makeCSR("spiffe://eggs-ample.org")
	cert, err := s.serverCA.SignCSR(context.Background(), csr, 0)
	s.requireErrorContains(err, `"spiffe://eggs-ample.org" does not belong to trust domain`)
	s.Require().Nil(cert)
}

func (s *ServerCASuite) TestSignCSRSuccess() {
	csr := s.makeCSR("spiffe://example.org")
	cert, err := s.serverCA.SignCSR(context.Background(), csr, 0)
	s.Require().NoError(err)

	s.Require().EqualValues(cert.URIs, []*url.URL{
		{Scheme: "spiffe", Host: "example.org"},
	})
	s.Require().False(cert.IsCA)
	s.Require().Equal("COMMONNAME", cert.Subject.CommonName)
	s.Require().NotEmpty(cert.SubjectKeyId)
	s.Require().Equal(
		x509.KeyUsageKeyEncipherment|x509.KeyUsageKeyAgreement|x509.KeyUsageDigitalSignature,
		cert.KeyUsage)
}

func (s *ServerCASuite) TestSignCSRCapsNotAfter() {
	csr := s.makeCSR("spiffe://example.org")
	cert, err := s.serverCA.SignCSR(context.Background(), csr, time.Hour*3)
	s.Require().NoError(err)

	s.Require().Equal(s.caCert.NotAfter, cert.NotAfter)
}
