package x509util

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/spiffe/spire/pkg/common/cryptoutil"
)

const (
	unknowAuthorityErr = "x509: certificate signed by unknown authority"
)

func CreateCertificate(template, parent *x509.Certificate, pub, priv any) (*x509.Certificate, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDER)
}

func CertificateMatchesPublicKey(certificate *x509.Certificate, publicKey crypto.PublicKey) (bool, error) {
	return cryptoutil.PublicKeyEqual(certificate.PublicKey, publicKey)
}

func CertificateMatchesPrivateKey(certificate *x509.Certificate, privateKey crypto.PrivateKey) (bool, error) {
	return cryptoutil.KeyMatches(privateKey, certificate.PublicKey)
}

func DedupeCertificates(bundles ...[]*x509.Certificate) []*x509.Certificate {
	certs := []*x509.Certificate{}

	// Retain ordering for easier testing
	seenMap := map[string]struct{}{}
	for _, bundle := range bundles {
		for _, cert := range bundle {
			if _, ok := seenMap[string(cert.Raw)]; !ok {
				seenMap[string(cert.Raw)] = struct{}{}
				certs = append(certs, cert)
			}
		}
	}

	return certs
}

func DERFromCertificates(certs []*x509.Certificate) (derBytes []byte) {
	for _, cert := range certs {
		derBytes = append(derBytes, cert.Raw...)
	}
	return derBytes
}

// RawCertsToCertificates parses certificates from the given slice of ASN.1 DER data
func RawCertsToCertificates(rawCerts [][]byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, rawCert := range rawCerts {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// RawCertsFromCertificates parses ASN.1 DER data from given slice of X.509 Certificates
func RawCertsFromCertificates(certs []*x509.Certificate) [][]byte {
	if certs == nil {
		return nil
	}
	rawCerts := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		rawCerts = append(rawCerts, cert.Raw)
	}
	return rawCerts
}

// IsUnknownAuthorityError returns tru if the Server returned an unknow authority error when verifying
// presented SVID
func IsUnknownAuthorityError(err error) bool {
	if err == nil {
		return false
	}

	// Since it is an rpc error we are unable to use errors.As since it is not possible to unwrap
	return strings.Contains(err.Error(), unknowAuthorityErr)
}

// IsSignedByRoot checks if the provided certificate chain is signed by one of the specified root CAs.
func IsSignedByRoot(chain []*x509.Certificate, rootCAs []*x509.Certificate) (bool, error) {
	if len(chain) == 0 {
		return false, nil
	}
	rootPool := x509.NewCertPool()
	for _, x509Authority := range rootCAs {
		rootPool.AddCert(x509Authority)
	}

	intermediatePool := x509.NewCertPool()
	for _, intermediateCA := range chain[1:] {
		intermediatePool.AddCert(intermediateCA)
	}

	// Verify certificate chain, using tainted authorities as root
	_, err := chain[0].Verify(x509.VerifyOptions{
		Intermediates: intermediatePool,
		Roots:         rootPool,
	})
	if err == nil {
		return true, nil
	}

	if IsUnknownAuthorityError(err) {
		return false, nil
	}

	return false, fmt.Errorf("failed to verify certificate chain: %w", err)
}
