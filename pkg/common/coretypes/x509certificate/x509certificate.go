package x509certificate

import (
	"crypto/x509"
	"errors"
	"fmt"
)

func fromProtoFields(asn1 []byte) (*x509.Certificate, error) {
	if len(asn1) == 0 {
		return nil, errors.New("missing X.509 certificate data")
	}
	x509Certificate, err := x509.ParseCertificate(asn1)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate data: %w", err)
	}
	return x509Certificate, nil
}

func rawFromProtoFields(asn1 []byte) ([]byte, error) {
	cert, err := fromProtoFields(asn1)
	if err != nil {
		return nil, err
	}
	return cert.Raw, nil
}

func toProtoFields(x509Certificate *x509.Certificate) ([]byte, error) {
	return rawToProtoFields(x509Certificate.Raw)
}

func rawToProtoFields(asn1 []byte) ([]byte, error) {
	if len(asn1) == 0 {
		return nil, errors.New("missing X.509 certificate data")
	}
	return asn1, nil
}
