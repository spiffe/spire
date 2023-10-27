package x509util

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
)

type Keypair interface {
	// GetCertificate returns the keypair certificate. It is called for each
	// signing request.
	GetCertificate(ctx context.Context) (*x509.Certificate, error)

	// CreateCertificate signs a certificate with the keypair.
	CreateCertificate(ctx context.Context, template *x509.Certificate, publicKey any) (certDER []byte, err error)
}

type MemoryKeypair struct {
	cert *x509.Certificate
	key  crypto.PrivateKey
}

func NewMemoryKeypair(cert *x509.Certificate, key crypto.PrivateKey) *MemoryKeypair {
	return &MemoryKeypair{
		cert: cert,
		key:  key,
	}
}

func (m *MemoryKeypair) GetCertificate(_ context.Context) (*x509.Certificate, error) {
	return m.cert, nil
}

func (m *MemoryKeypair) CreateCertificate(_ context.Context, template *x509.Certificate, publicKey any) ([]byte, error) {
	return x509.CreateCertificate(rand.Reader, template, m.cert, publicKey, m.key)
}
