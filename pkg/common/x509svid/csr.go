package x509svid

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func ParseAndValidateCSR(csrDER []byte, td spiffeid.TrustDomain) (csr *x509.CertificateRequest, err error) {
	csr, err = x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("unable to parse CSR: %w", err)
	}

	if err := ValidateCSR(csr, td); err != nil {
		return nil, err
	}

	return csr, nil
}

func ValidateCSR(csr *x509.CertificateRequest, td spiffeid.TrustDomain) error {
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("CSR signature check failed: %w", err)
	}

	if len(csr.URIs) != 1 {
		return errors.New("CSR must have exactly one URI SAN")
	}

	id, err := spiffeid.FromURI(csr.URIs[0])
	if err != nil {
		return fmt.Errorf("CSR with SPIFFE ID %q is invalid: %w", csr.URIs[0], err)
	}
	if id != td.ID() {
		return fmt.Errorf("CSR with SPIFFE ID %q is invalid: must use the trust domain ID for trust domain %q", id, td)
	}
	return nil
}
