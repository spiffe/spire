package services

import "github.com/spiffe/sri/pkg/server/ca"

//CA service interface.
type CA interface {
	SignCsr(csr []byte) (cert []byte, err error)
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
