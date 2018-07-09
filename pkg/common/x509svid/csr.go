package x509svid

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/uri"
	"github.com/spiffe/spire/pkg/common/idutil"
)

func ParseAndValidateCSR(csrDER []byte, validationMode idutil.ValidationMode) (csr *x509.CertificateRequest, err error) {
	csr, err = x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("unable to parse CSR: %v", err)
	}

	if err := ValidateCSR(csr, validationMode); err != nil {
		return nil, err
	}

	return csr, nil
}

func ValidateCSR(csr *x509.CertificateRequest, validationMode idutil.ValidationMode) error {
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("CSR signature check failed: %v", err)
	}

	urinames, err := uri.GetURINamesFromExtensions(&csr.Extensions)
	if err != nil {
		return err
	}
	if len(urinames) != 1 {
		return errors.New("CSR must have exactly one URI SAN")
	}

	if err := idutil.ValidateSpiffeID(urinames[0], validationMode); err != nil {
		return err
	}

	return nil
}
