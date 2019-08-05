package bundle

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
)

func SPIFFEAuth(getter func() ([]*x509.Certificate, crypto.PrivateKey, error)) ServerAuth {
	return &spiffeAuth{
		getter: getter,
	}
}

type spiffeAuth struct {
	getter func() ([]*x509.Certificate, crypto.PrivateKey, error)
}

func (s *spiffeAuth) GetTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: s.getCertificate,
	}
}

func (s *spiffeAuth) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	chain, privateKey, err := s.getter()
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: chainDER(chain),
		PrivateKey:  privateKey,
	}, nil
}
