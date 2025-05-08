package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/test/clock"
)

// NewCSRTemplate returns a default CSR template with the specified SPIFFE ID.
func NewCSRTemplate(spiffeID string) ([]byte, crypto.PublicKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := NewCSRTemplateWithKey(spiffeID, key)
	if err != nil {
		return nil, nil, err
	}
	return csr, key.Public(), nil
}

func NewCSRTemplateWithKey(spiffeID string, key crypto.Signer) ([]byte, error) {
	uriSAN, err := url.Parse(spiffeID)
	if err != nil {
		return nil, err
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SPIRE"},
		},
		URIs: []*url.URL{uriSAN},
	}
	return x509.CreateCertificateRequest(rand.Reader, template, key)
}

// NewSVIDTemplate returns a default SVID template with the specified SPIFFE ID. Must
// be signed before it's valid.
func NewSVIDTemplate(clk clock.Clock, spiffeID string) (*x509.Certificate, error) {
	cert := defaultSVIDTemplate(clk)
	err := addSpiffeExtension(spiffeID, cert)

	return cert, err
}

// NewCATemplate returns a default CA template with the specified trust domain. Must
// be signed before it's valid.
func NewCATemplate(clk clock.Clock, trustDomain spiffeid.TrustDomain) (*x509.Certificate, error) {
	cert := defaultCATemplate(clk)
	err := addSpiffeExtension(trustDomain.IDString(), cert)

	return cert, err
}

// SelfSign creates a new self-signed certificate with the provided template.
func SelfSign(req *x509.Certificate) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	return Sign(req, req, nil)
}

// Sign creates a new certificate based on the provided template and signed using parent
// certificate and signerPrivateKey.
func Sign(req, parent *x509.Certificate, signerPrivateKey any) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	var err error
	var key *ecdsa.PrivateKey

	publicKey, ok := req.PublicKey.(crypto.PublicKey)
	if !ok {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		publicKey = key.Public()
		skID, err := x509util.GetSubjectKeyID(publicKey)
		if err != nil {
			return nil, nil, err
		}
		req.SubjectKeyId = skID
	}

	if signerPrivateKey == nil {
		signerPrivateKey = key
	}

	if req.SerialNumber == nil {
		req.SerialNumber = randomSerial()
	}

	certData, err := x509.CreateCertificate(rand.Reader, req, parent, publicKey, signerPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

// Returns an SVID template with many default values set. Should be overwritten prior to
// generating a new test SVID
func defaultSVIDTemplate(clk clock.Clock) *x509.Certificate {
	now := clk.Now()
	return &x509.Certificate{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SPIRE"},
		},
		NotBefore: now,
		NotAfter:  now.Add(1 * time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageKeyAgreement |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
}

// Returns an CA template with many default values set.
func defaultCATemplate(clk clock.Clock) *x509.Certificate {
	now := clk.Now()
	name := pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"SPIRE"},
	}
	return &x509.Certificate{
		Subject:               name,
		Issuer:                name,
		IsCA:                  true,
		NotBefore:             now,
		NotAfter:              now.Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
}

// Create an x509 extension with the URI SAN of the given SPIFFE ID, and set it onto
// the referenced certificate
func addSpiffeExtension(spiffeID string, cert *x509.Certificate) error {
	u, err := url.Parse(spiffeID)
	if err != nil {
		return err
	}
	cert.URIs = append(cert.URIs, u)
	return nil
}

// Creates a random certificate serial number
func randomSerial() *big.Int {
	serial, _ := rand.Int(rand.Reader, big.NewInt(1337))
	return serial
}
