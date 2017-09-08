package services

//go:generate mockgen -source=$GOFILE -destination=attestation_mock.go -package=$GOPACKAGE

import (
	"crypto/x509"
	"time"

	"github.com/spiffe/spire/pkg/common"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/nodeattestor"
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
func NewAttestationImpl(dataStore datastore.DataStore, nodeAttestor nodeattestor.NodeAttestor) *AttestationImpl {
	return &AttestationImpl{
		dataStore:    dataStore,
		nodeAttestor: nodeAttestor,
	}
}

//IsAttested checks the datastore to see if the baseSpiffeID was already attested.
func (att *AttestationImpl) IsAttested(baseSpiffeID string) (isAttested bool, err error) {
	var fetchResponse *datastore.FetchAttestedNodeEntryResponse
	fetchRequest := &datastore.FetchAttestedNodeEntryRequest{BaseSpiffeId: baseSpiffeID}
	fetchResponse, err = att.dataStore.FetchAttestedNodeEntry(fetchRequest)
	if err != nil || fetchResponse.AttestedNodeEntry == nil {
		return false, err
	}
	if fetchResponse.AttestedNodeEntry.BaseSpiffeId == baseSpiffeID {
		return true, nil
	}
	return false, nil
}

//Attest the attestedData
func (att *AttestationImpl) Attest(attestedData *common.AttestedData, attestedBefore bool) (attestResponse *nodeattestor.AttestResponse, err error) {
	attestRequest := &nodeattestor.AttestRequest{
		AttestedData:   attestedData,
		AttestedBefore: attestedBefore,
	}
	return att.nodeAttestor.Attest(attestRequest)
}

func (att *AttestationImpl) CreateEntry(attestationType string, baseSpiffeID string, certBytes []byte) (err error) {
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return err
	}

	attestedNodeRequest := &datastore.CreateAttestedNodeEntryRequest{AttestedNodeEntry: &datastore.AttestedNodeEntry{
		AttestedDataType:   attestationType,
		BaseSpiffeId:       baseSpiffeID,
		CertExpirationDate: cert.NotAfter.Format(time.RFC1123Z),
		CertSerialNumber:   cert.SerialNumber.String(),
	}}
	_, err = att.dataStore.CreateAttestedNodeEntry(attestedNodeRequest)
	return err
}

func (att *AttestationImpl) UpdateEntry(baseSpiffeID string, certBytes []byte) (err error) {
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return err
	}

	_, err = att.dataStore.UpdateAttestedNodeEntry(&datastore.UpdateAttestedNodeEntryRequest{
		BaseSpiffeId:       baseSpiffeID,
		CertExpirationDate: cert.NotAfter.Format(time.RFC1123Z),
		CertSerialNumber:   cert.SerialNumber.String(),
	})
	return err
}
