package services

import (
	"github.com/spiffe/sri/pkg/common"
	"github.com/spiffe/sri/pkg/server/nodeattestor"
)

//AttestationMock
type AttestationMock struct {
}

func (mock *AttestationMock) IsAttested(baseSpiffeID string) (isAttested bool, err error) {
	return false, nil
}
func (mock *AttestationMock) Attest(attestedData *common.AttestedData, attestedBefore bool) (attestResponse *nodeattestor.AttestResponse, err error) {
	return nil, nil
}
func (mock *AttestationMock) CreateEntry(attestationType string, baseSpiffeID string, cert []byte) (err error) {
	return nil
}
func (mock *AttestationMock) UpdateEntry(baseSpiffeID string, cert []byte) (err error) {
	return nil
}
