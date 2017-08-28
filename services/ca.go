package services

import (
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/spiffe/go-spiffe/uri"
	"github.com/spiffe/sri/pkg/server/ca"
)

//CA service interface.
type CA interface {
	SignCsr(csr []byte) (cert []byte, err error)
	GetSpiffeIDFromCSR(csr []byte) (spiffeID string, err error)
}

//CAImpl is an implementation of the CA interface.
type CAImpl struct {
	serverCA ca.ControlPlaneCa
}

//NewCAImpl creastes a new CAImpl.
func NewCAImpl(serverCA ca.ControlPlaneCa) *CAImpl {
	return &CAImpl{serverCA: serverCA}
}

//SignCsr with the stored intermediate certificate.
func (ca *CAImpl) SignCsr(csr []byte) (cert []byte, err error) {
	return ca.serverCA.SignCsr(csr)
}

//GetSpiffeIDFromCSR extracts an SpiffeID from a CSR
func (ca *CAImpl) GetSpiffeIDFromCSR(csr []byte) (spiffeID string, err error) {
	block, _ := pem.Decode(csr)
	var parsedCSR *x509.CertificateRequest
	if parsedCSR, err = x509.ParseCertificateRequest(block.Bytes); err != nil {
		return spiffeID, err
	}

	var uris []string
	uris, err = uri.GetURINamesFromExtensions(&parsedCSR.Extensions)

	if len(uris) != 1 {
		return spiffeID, errors.New("The CSR must have exactly one URI SAN")
	}

	spiffeID = uris[0]
	return spiffeID, nil
}
