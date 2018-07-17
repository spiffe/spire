package pemutil

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/suite"
)

func Test(t *testing.T) {
	suite.Run(t, new(Suite))
}

type Suite struct {
	suite.Suite
}

func (s *Suite) TestParsePrivateKey() {
	// not a private key
	_, err := ParsePrivateKey(s.readFile("testdata/cert.pem"))
	s.Require().EqualError(err, `expected block type ["PRIVATE KEY" "RSA PRIVATE KEY" "EC PRIVATE KEY"]; got "CERTIFICATE"`)

	// success with RSA
	key, err := ParsePrivateKey(s.readFile("testdata/rsa-key.pem"))
	s.Require().NoError(err)
	s.Require().NotNil(key)
	_, ok := key.(*rsa.PrivateKey)
	s.Require().True(ok)

	// success with RSA PKCS8
	key, err = ParsePrivateKey(s.readFile("testdata/rsa-key-pkcs8.pem"))
	s.Require().NoError(err)
	s.Require().NotNil(key)
	_, ok = key.(*rsa.PrivateKey)
	s.Require().True(ok)

	// success with ECDSA
	key, err = ParsePrivateKey(s.readFile("testdata/ecdsa-key.pem"))
	s.Require().NoError(err)
	s.Require().NotNil(key)
	_, ok = key.(*ecdsa.PrivateKey)
	s.Require().True(ok)

	// success with ECDSA PKCS8
	key, err = ParsePrivateKey(s.readFile("testdata/ecdsa-key-pkcs8.pem"))
	s.Require().NoError(err)
	s.Require().NotNil(key)
	_, ok = key.(*ecdsa.PrivateKey)
	s.Require().True(ok)
}

func (s *Suite) TestLoadPrivateKey() {
	// not a private key
	_, err := LoadPrivateKey("testdata/cert.pem")
	s.Require().EqualError(err, `expected block type ["PRIVATE KEY" "RSA PRIVATE KEY" "EC PRIVATE KEY"]; got "CERTIFICATE"`)

	// success with RSA
	key, err := LoadPrivateKey("testdata/rsa-key.pem")
	s.Require().NoError(err)
	s.Require().NotNil(key)
	_, ok := key.(*rsa.PrivateKey)
	s.Require().True(ok)

	// success with RSA PKCS8
	key, err = LoadPrivateKey("testdata/rsa-key-pkcs8.pem")
	s.Require().NoError(err)
	s.Require().NotNil(key)
	_, ok = key.(*rsa.PrivateKey)
	s.Require().True(ok)

	// success with ECDSA
	key, err = LoadPrivateKey("testdata/ecdsa-key.pem")
	s.Require().NoError(err)
	s.Require().NotNil(key)
	_, ok = key.(*ecdsa.PrivateKey)
	s.Require().True(ok)

	key, err = LoadPrivateKey("testdata/ecdsa-key-pkcs8.pem")
	s.Require().NoError(err)
	s.Require().NotNil(key)
	_, ok = key.(*ecdsa.PrivateKey)
	s.Require().True(ok)
}

func (s *Suite) TestParseRSAPrivateKey() {
	// not a private key
	_, err := ParseRSAPrivateKey(s.readFile("testdata/cert.pem"))
	s.Require().EqualError(err, `expected block type ["PRIVATE KEY" "RSA PRIVATE KEY"]; got "CERTIFICATE"`)

	// not an RSA private key
	_, err = ParseRSAPrivateKey(s.readFile("testdata/ecdsa-key-pkcs8.pem"))
	s.Require().EqualError(err, "expected *rsa.PrivateKey; got *ecdsa.PrivateKey")

	// success
	key, err := ParseRSAPrivateKey(s.readFile("testdata/rsa-key.pem"))
	s.Require().NoError(err)
	s.Require().NotNil(key)

	// success (pkcs8)
	key, err = ParseRSAPrivateKey(s.readFile("testdata/rsa-key-pkcs8.pem"))
	s.Require().NoError(err)
	s.Require().NotNil(key)
}

func (s *Suite) TestLoadRSAPrivateKey() {
	// not a private key
	_, err := LoadRSAPrivateKey("testdata/cert.pem")
	s.Require().EqualError(err, `expected block type ["PRIVATE KEY" "RSA PRIVATE KEY"]; got "CERTIFICATE"`)

	// not an RSA private key
	_, err = LoadRSAPrivateKey("testdata/ecdsa-key-pkcs8.pem")
	s.Require().EqualError(err, "expected *rsa.PrivateKey; got *ecdsa.PrivateKey")

	// success
	key, err := LoadRSAPrivateKey("testdata/rsa-key.pem")
	s.Require().NoError(err)
	s.Require().NotNil(key)

	// success (pkcs8)
	key, err = LoadRSAPrivateKey("testdata/rsa-key-pkcs8.pem")
	s.Require().NoError(err)
	s.Require().NotNil(key)
}

func (s *Suite) TestParseECPrivateKey() {
	// not a private key
	_, err := ParseECPrivateKey(s.readFile("testdata/cert.pem"))
	s.Require().EqualError(err, `expected block type ["PRIVATE KEY" "EC PRIVATE KEY"]; got "CERTIFICATE"`)

	// not an ECDSA private key
	_, err = ParseECPrivateKey(s.readFile("testdata/rsa-key-pkcs8.pem"))
	s.Require().EqualError(err, "expected *ecdsa.PrivateKey; got *rsa.PrivateKey")

	// success
	key, err := ParseECPrivateKey(s.readFile("testdata/ecdsa-key.pem"))
	s.Require().NoError(err)
	s.Require().NotNil(key)

	// success (pkcs8)
	key, err = ParseECPrivateKey(s.readFile("testdata/ecdsa-key-pkcs8.pem"))
	s.Require().NoError(err)
	s.Require().NotNil(key)
}

func (s *Suite) TestLoadECPrivateKey() {
	// not a private key
	_, err := LoadECPrivateKey("testdata/cert.pem")
	s.Require().EqualError(err, `expected block type ["PRIVATE KEY" "EC PRIVATE KEY"]; got "CERTIFICATE"`)

	// not an ECDSA private key
	_, err = LoadECPrivateKey("testdata/rsa-key-pkcs8.pem")
	s.Require().EqualError(err, "expected *ecdsa.PrivateKey; got *rsa.PrivateKey")

	// success
	key, err := LoadECPrivateKey("testdata/ecdsa-key.pem")
	s.Require().NoError(err)
	s.Require().NotNil(key)

	// success (pkcs8)
	key, err = LoadECPrivateKey("testdata/ecdsa-key-pkcs8.pem")
	s.Require().NoError(err)
	s.Require().NotNil(key)

}

func (s *Suite) TestParseCertificate() {
	// not a certificate
	_, err := ParseCertificate(s.readFile("testdata/rsa-key-pkcs8.pem"))
	s.Require().EqualError(err, `expected block type "CERTIFICATE"; got "PRIVATE KEY"`)

	// success
	cert, err := ParseCertificate(s.readFile("testdata/cert.pem"))
	s.Require().NoError(err)
	s.Require().NotNil(cert)
}

func (s *Suite) TestLoadCertificate() {
	// not a certificate
	_, err := LoadCertificate("testdata/rsa-key-pkcs8.pem")
	s.Require().EqualError(err, `expected block type "CERTIFICATE"; got "PRIVATE KEY"`)

	// success
	cert, err := LoadCertificate("testdata/cert.pem")
	s.Require().NoError(err)
	s.Require().NotNil(cert)
}

func (s *Suite) TestParseCertificates() {
	// not a certificate
	_, err := ParseCertificates(s.readFile("testdata/rsa-key-pkcs8.pem"))
	s.Require().EqualError(err, `expected block type "CERTIFICATE"; got "PRIVATE KEY"`)

	// success with one certificate
	cert, err := ParseCertificates(s.readFile("testdata/cert.pem"))
	s.Require().NoError(err)
	s.Require().NotNil(cert)

	// success with multiple certificates
	certs, err := ParseCertificates(s.readFile("testdata/certs.pem"))
	s.Require().NoError(err)
	s.Require().Len(certs, 2)
}

func (s *Suite) TestLoadCertificates() {
	// not a certificate
	_, err := LoadCertificates("testdata/rsa-key-pkcs8.pem")
	s.Require().EqualError(err, `expected block type "CERTIFICATE"; got "PRIVATE KEY"`)

	// success with one certificate
	cert, err := LoadCertificates("testdata/cert.pem")
	s.Require().NoError(err)
	s.Require().NotNil(cert)

	// success with multiple certificates
	certs, err := LoadCertificates("testdata/certs.pem")
	s.Require().NoError(err)
	s.Require().Len(certs, 2)
}

func (s *Suite) TestParseCertificateRequest() {
	// not a csr
	_, err := ParseCertificateRequest(s.readFile("testdata/rsa-key-pkcs8.pem"))
	s.Require().EqualError(err, `expected block type "CERTIFICATE REQUEST"; got "PRIVATE KEY"`)

	// success
	csr, err := ParseCertificateRequest(s.readFile("testdata/csr.pem"))
	s.Require().NoError(err)
	s.Require().NotNil(csr)
}

func (s *Suite) TestLoadCertificateRequest() {
	// not a csr
	_, err := LoadCertificateRequest("testdata/rsa-key-pkcs8.pem")
	s.Require().EqualError(err, `expected block type "CERTIFICATE REQUEST"; got "PRIVATE KEY"`)

	// success
	csr, err := LoadCertificateRequest("testdata/csr.pem")
	s.Require().NoError(err)
	s.Require().NotNil(csr)
}

func (s *Suite) readFile(path string) []byte {
	data, err := ioutil.ReadFile(path)
	s.Require().NoError(err)
	return data
}
