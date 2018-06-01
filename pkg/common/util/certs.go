package util

import "crypto/x509"

// NewCertPool creates a new *x509.CertPool based on the certificates given
// as parameters.
func NewCertPool(certs ...*x509.Certificate) *x509.CertPool {
	certPool := x509.NewCertPool()
	for _, cert := range certs {
		certPool.AddCert(cert)
	}
	return certPool
}
