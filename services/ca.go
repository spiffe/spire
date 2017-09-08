package services

//go:generate mockgen -source=$GOFILE -destination=ca_mock.go -package=$GOPACKAGE

import (
	"crypto/x509"
	"errors"

	"github.com/spiffe/go-spiffe/uri"
	"github.com/spiffe/spire/pkg/server/ca"
)

//CA service interface.
type CA interface {
	SignCsr(request *ca.SignCsrRequest) (response *ca.SignCsrResponse, err error)
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
func (ca *CAImpl) SignCsr(request *ca.SignCsrRequest) (response *ca.SignCsrResponse, err error) {
	return ca.serverCA.SignCsr(request)
}

//GetSpiffeIDFromCSR extracts an SpiffeID from a CSR
func (ca *CAImpl) GetSpiffeIDFromCSR(csr []byte) (spiffeID string, err error) {
	var parsedCSR *x509.CertificateRequest
	if parsedCSR, err = x509.ParseCertificateRequest(csr); err != nil {
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
