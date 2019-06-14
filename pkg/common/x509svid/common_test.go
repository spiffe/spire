package x509svid

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"time"

	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/stretchr/testify/suite"
)

var (
	caKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgxnHYJV9OhsaLtuaW
/7IPE9LlYfK/C0xcS79rbmMirwyhRANCAASMzb/ZSOqEOzb5zkcdTuSseQ42iGX8
o9Y0GCw8muyyCRtMBEjSuD4FTZsBtAabaGhGMPigls3wUmJDt4nD2tB/
-----END PRIVATE KEY-----
`)

	csrKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgckPbYRXwHRnSK2gU
CfWxSiBxY72Vz4zQvxV2VoDNepGhRANCAATAJwLrooS7CpWTGtl8ktJJY+CZpOYH
vXby7YvalD2VYpfd7xH1lkRQzIPi6mABuaX1EzZKfbWaW/MF+Vz6qDrK
-----END PRIVATE KEY-----
`)
)

type caSuite struct {
	suite.Suite

	caCert  *x509.Certificate
	csrKey  *ecdsa.PrivateKey
	keypair *x509util.MemoryKeypair
}

func (s *caSuite) SetupTest() {
	caKey := s.loadKey(caKeyPEM)
	caCert := s.createCA(caKey, 2*time.Hour)
	s.caCert = caCert
	s.csrKey = s.loadKey(csrKeyPEM)
	s.keypair = x509util.NewMemoryKeypair(caCert, caKey)
}

func (s *caSuite) createCA(key *ecdsa.PrivateKey, ttl time.Duration) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotAfter:              time.Now().Add(ttl),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	s.Require().NoError(err)
	cert, err := x509.ParseCertificate(certDER)
	s.Require().NoError(err)
	return cert
}

func (s *caSuite) loadKey(pemBytes []byte) *ecdsa.PrivateKey {
	pemBlock, rest := pem.Decode(pemBytes)
	s.Require().NotNil(pemBlock)
	s.Require().Empty(rest)
	rawKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	s.Require().NoError(err)
	key, ok := rawKey.(*ecdsa.PrivateKey)
	s.Require().True(ok)
	return key
}

func (s *caSuite) makeCSR(spiffeID string) []byte {
	var uris []*url.URL
	if spiffeID != "" {
		u, err := url.Parse(spiffeID)
		s.Require().NoError(err)
		uris = append(uris, u)
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "COMMONNAME",
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		URIs:               uris,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, s.csrKey)
	s.Require().NoError(err)
	return csr
}

func (s *caSuite) requireErrorContains(err error, contains string) {
	s.Require().Error(err)
	s.Require().Contains(err.Error(), contains)
}
