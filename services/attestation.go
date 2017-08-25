package services

import (
	"github.com/spiffe/sri/pkg/common"
	"github.com/spiffe/sri/pkg/server/datastore"
	"github.com/spiffe/sri/pkg/server/nodeattestor"
)

//Attestation service interface.
type Attestation interface {
	IsAttested(baseSpiffeID string) (isAttested bool, err error)
	Attest(attestedData *common.AttestedData, attestedBefore bool) (attestResponse *nodeattestor.AttestResponse, err error)
	CreateEntry(attestationType string, baseSpiffeID string, cert []byte) (err error)
	UpdateEntry(baseSpiffeID string, cert []byte) (err error)
}

//AttestationImpl is an implementation of the Attestation interface.
type AttestationImpl struct {
	dataStore    datastore.DataStore
	nodeAttestor nodeattestor.NodeAttestor
}

//NewAttestationImpl creastes a new AttestationImpl.
func NewAttestationImpl(dataStore datastore.DataStore, nodeAttestor nodeattestor.NodeAttestor) AttestationImpl {
	return AttestationImpl{
		dataStore:    dataStore,
		nodeAttestor: nodeAttestor,
	}
}

//IsAttested checks the datastore to see if the baseSpiffeID was already attested.
func (att AttestationImpl) IsAttested(baseSpiffeID string) (isAttested bool, err error) {
	var fetchResponse *datastore.FetchAttestedNodeEntryResponse
	fetchRequest := &datastore.FetchAttestedNodeEntryRequest{BaseSpiffeId: baseSpiffeID}
	if fetchResponse, err = att.dataStore.FetchAttestedNodeEntry(fetchRequest); err != nil {
		return false, err
	}
	if fetchResponse.AttestedNodeEntry.BaseSpiffeId == "" {
		return true, nil
	}
	return false, nil
}

//Attest the attestedData
func (att AttestationImpl) Attest(attestedData *common.AttestedData, attestedBefore bool) (attestResponse *nodeattestor.AttestResponse, err error) {
	attestRequest := &nodeattestor.AttestRequest{
		AttestedData:   attestedData,
		AttestedBefore: attestedBefore,
	}
	return att.nodeAttestor.Attest(attestRequest)
}

func (att AttestationImpl) CreateEntry(attestationType string, baseSpiffeID string, cert []byte) (err error) {
	//TODO:extract CertExpirationDate and CertSerialNumber @kunzimariano
	attestedNodeRequest := &datastore.CreateAttestedNodeEntryRequest{AttestedNodeEntry: &datastore.AttestedNodeEntry{
		AttestedDataType:   attestationType,
		BaseSpiffeId:       baseSpiffeID,
		CertExpirationDate: "",
		CertSerialNumber:   "",
	}}
	_, err = att.dataStore.CreateAttestedNodeEntry(attestedNodeRequest)
	return err
}

func (att AttestationImpl) UpdateEntry(baseSpiffeID string, cert []byte) (err error) {
	//TODO:extract CertExpirationDate and CertSerialNumber @kunzimariano
	_, err = att.dataStore.UpdateAttestedNodeEntry(&datastore.UpdateAttestedNodeEntryRequest{
		BaseSpiffeId:       baseSpiffeID,
		CertExpirationDate: "",
		CertSerialNumber:   "",
	})
	return err
}
