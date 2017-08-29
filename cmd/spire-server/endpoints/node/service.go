package node

import (
	"context"
	"errors"

	pb "github.com/spiffe/sri/pkg/api/node"
	"github.com/spiffe/sri/pkg/common"
	"github.com/spiffe/sri/pkg/server/nodeattestor"
	"github.com/spiffe/sri/services"
)

// Implement yor service methods methods.
// e.x: Foo(ctx context.Context,s string)(rs string, err error)
type NodeService interface {
	FetchBaseSVID(ctx context.Context, request pb.FetchBaseSVIDRequest) (response pb.FetchBaseSVIDResponse, err error)
	FetchSVID(ctx context.Context, request pb.FetchSVIDRequest) (response pb.FetchSVIDResponse)
	FetchCPBundle(ctx context.Context, request pb.FetchCPBundleRequest) (response pb.FetchCPBundleResponse)
	FetchFederatedBundle(ctx context.Context, request pb.FetchFederatedBundleRequest) (response pb.FetchFederatedBundleResponse)
}

type stubNodeService struct {
	attestation services.Attestation
	identity    services.Identity
	ca          services.CA
}

// NewService gets a new instance of the service.
func NewService(
	attestation services.Attestation,
	identity services.Identity,
	ca services.CA) (s *stubNodeService) {

	s = &stubNodeService{
		attestation: attestation,
		identity:    identity,
		ca:          ca,
	}
	return s
}

// Implement the business logic of FetchBaseSVID
func (no *stubNodeService) FetchBaseSVID(ctx context.Context, request pb.FetchBaseSVIDRequest) (response pb.FetchBaseSVIDResponse, err error) {
	//Attest the node and get baseSpiffeID
	baseSpiffeIDFromCSR, err := no.ca.GetSpiffeIDFromCSR(request.Csr)
	if err != nil {
		return
	}

	attestedBefore, err := no.attestation.IsAttested(baseSpiffeIDFromCSR)
	if err != nil {
		return

	}
	var attestResponse *nodeattestor.AttestResponse

	attestResponse, err = no.attestation.Attest(request.AttestedData, attestedBefore)
	if err != nil {
		return
	}

	//Validate
	if !attestResponse.Valid {
		return response, errors.New("Invalid")
	}

	//check if baseSPIFFEID in attest response matches with SPIFFEID in CSR
	if attestResponse.BaseSPIFFEID != baseSpiffeIDFromCSR {
		return response, errors.New("BaseSPIFFEID MisMatch")
	}

	//Sign csr
	var cert []byte
	if cert, err = no.ca.SignCsr(request.Csr); err != nil {
		return response, err
	}

	baseSpiffeID := attestResponse.BaseSPIFFEID
	if attestedBefore {
		//UPDATE attested node entry
		if no.attestation.UpdateEntry(baseSpiffeID, cert); err != nil {
			return response, err
		}

	} else {
		//CREATE attested node entry
		if no.attestation.CreateEntry(request.AttestedData.Type, baseSpiffeID, cert); err != nil {
			return response, err
		}
	}

	//Call node resolver plugin to get a map of {Spiffe ID,[ ]Selector}
	var selectors map[string]*common.Selectors
	if selectors, err = no.identity.Resolve([]string{baseSpiffeID}); err != nil {
		return response, err
	}

	if no.identity.CreateEntry(baseSpiffeID, selectors[baseSpiffeID].Entries[0]); err != nil {
		return response, err
	}

	m := make(map[string]*pb.Svid)
	m[baseSpiffeID] = &pb.Svid{SvidCert: cert, Ttl: 999}
	svidMap := &pb.SvidMap{Map: m}
	registrationEntry := &common.RegistrationEntry{
		SpiffeId:  baseSpiffeID,
		Selectors: selectors[baseSpiffeID].Entries,
	}
	svidUpdate := &pb.SvidUpdate{
		SvidMap:               svidMap,
		RegistrationEntryList: []*common.RegistrationEntry{registrationEntry},
	}
	response = pb.FetchBaseSVIDResponse{SpiffeEntry: svidUpdate}

	return
}

// Implement the business logic of FetchSVID
func (no *stubNodeService) FetchSVID(ctx context.Context, request pb.FetchSVIDRequest) (response pb.FetchSVIDResponse) {
	return response
}

// Implement the business logic of FetchCPBundle
func (no *stubNodeService) FetchCPBundle(ctx context.Context, request pb.FetchCPBundleRequest) (response pb.FetchCPBundleResponse) {
	return response
}

// Implement the business logic of FetchFederatedBundle
func (no *stubNodeService) FetchFederatedBundle(ctx context.Context, request pb.FetchFederatedBundleRequest) (response pb.FetchFederatedBundleResponse) {
	return response
}
