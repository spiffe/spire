package x509certificate

import (
	"crypto/x509"
	"errors"
	"fmt"
)

// TODO: may we call it Authority?
// TODO: may we add subjectKeyID?
type X509Authority struct {
	Certificate *x509.Certificate
	Tainted     bool
}

func fromProtoFields(asn1 []byte, tainted bool) (*X509Authority, error) {
	if len(asn1) == 0 {
		return nil, errors.New("missing X.509 certificate data")
	}
	x509Certificate, err := x509.ParseCertificate(asn1)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate data: %w", err)
	}
	return &X509Authority{
		Certificate: x509Certificate,
		Tainted:     tainted,
	}, nil
}

func toProtoFields(x509Authority *X509Authority) ([]byte, bool, error) {
	if x509Authority == nil {
		return nil, false, errors.New("missing x509 authority")
	}
	if err := validateX509Certificate(x509Authority.Certificate); err != nil {
		return nil, false, err
	}

	return x509Authority.Certificate.Raw, x509Authority.Tainted, nil
}

func validateX509Certificate(cert *x509.Certificate) error {
	switch {
	case cert == nil:
		return errors.New("missing X.509 certificate")
	case len(cert.Raw) == 0:
		return errors.New("missing X.509 certificate data")
	default:
		return nil
	}
}
