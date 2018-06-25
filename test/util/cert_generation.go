package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	mrand "math/rand"
	"time"

	"github.com/spiffe/go-spiffe/uri"
)

// NewSVIDTemplate returns a default SVID template with the specified SPIFFE ID. Must
// be signed before it's valid.
func NewSVIDTemplate(spiffeID string) (*x509.Certificate, error) {
	cert := defaultSVIDTemplate()
	err := addSpiffeExtension(spiffeID, cert)

	return cert, err
}

func NewSVIDTemplateFromCSR(csr []byte, ca *x509.Certificate, ttl int) (*x509.Certificate, error) {
	cr, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, err
	}

	cert := &x509.Certificate{
		Subject:            cr.Subject,
		Issuer:             ca.Subject,
		PublicKey:          cr.PublicKey,
		PublicKeyAlgorithm: cr.PublicKeyAlgorithm,
		Signature:          cr.Signature,
		SignatureAlgorithm: cr.SignatureAlgorithm,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(time.Duration(ttl) * time.Second),
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageKeyAgreement |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       cr.Extensions,
	}
	return cert, nil
}

// NewCATemplate returns a default CA template with the specified trust domain. Must
// be signed before it's valid.
func NewCATemplate(trustDomain string) (*x509.Certificate, error) {
	cert := defaultCATemplate()
	err := addSpiffeExtension("spiffe://"+trustDomain, cert)

	return cert, err
}

// SelfSign creates a new self-signed certificate with the provided template.
func SelfSign(req *x509.Certificate) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	return Sign(req, req, nil)
}

// Sign creates a new certificate based on the provided template and signed using parent
// certificate and signerPrivateKey.
func Sign(req, parent *x509.Certificate, signerPrivateKey interface{}) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	var err error
	var key *ecdsa.PrivateKey

	publicKey, ok := req.PublicKey.(crypto.PublicKey)
	if !ok {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		publicKey = key.Public()
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
func defaultSVIDTemplate() *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SPIRE"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(1 * time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageKeyAgreement |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
}

// Returns an CA template with many default values set.
func defaultCATemplate() *x509.Certificate {
	name := pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"SPIRE"},
	}
	return &x509.Certificate{
		Subject:               name,
		Issuer:                name,
		IsCA:                  true,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
}

// Create an x509 extension with the URI SAN of the given SPIFFE ID, and set it onto
// the referenced certificate
func addSpiffeExtension(spiffeID string, cert *x509.Certificate) error {
	uriSANs, err := uri.MarshalUriSANs([]string{spiffeID})
	if err != nil {
		return err
	}

	ext := []pkix.Extension{{
		Id:       uri.OidExtensionSubjectAltName,
		Value:    uriSANs,
		Critical: true,
	}}

	cert.ExtraExtensions = ext
	return nil
}

// Creates a random certificate serial number
func randomSerial() *big.Int {
	src := mrand.NewSource(1337)
	num := mrand.New(src).Int63()
	return big.NewInt(num)
}
