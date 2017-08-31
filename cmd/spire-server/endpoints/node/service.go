package node

import (
	"context"
	"errors"

	pb "github.com/spiffe/sri/pkg/api/node"
	"github.com/spiffe/sri/pkg/common"
	"github.com/spiffe/sri/pkg/server/nodeattestor"
	"github.com/spiffe/sri/services"
	"github.com/spiffe/sri/pkg/server/ca"
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
	attestation     services.Attestation
	identity        services.Identity
	ca              services.CA
	baseSpiffeIDTTL int32
}

//ServiceConfig is a configuration struct to init the service
type ServiceConfig struct {
	Attestation     services.Attestation
	Identity        services.Identity
	CA              services.CA
	BaseSpiffeIDTTL int32
}

// NewService gets a new instance of the service.
func NewService(config ServiceConfig) (s *stubNodeService) {
	s = &stubNodeService{
		attestation:     config.Attestation,
		identity:        config.Identity,
		ca:              config.CA,
		baseSpiffeIDTTL: config.BaseSpiffeIDTTL,
	}
	return s
}

// Implement the business logic of FetchBaseSVID
func (no *stubNodeService) FetchBaseSVID(ctx context.Context, request pb.FetchBaseSVIDRequest) (response pb.FetchBaseSVIDResponse, err error) {
	//Attest the node and get baseSpiffeID
	baseSpiffeIDFromCSR, err := no.ca.GetSpiffeIDFromCSR(request.Csr)
	if err != nil {
		return response, err
	}

	attestedBefore, err := no.attestation.IsAttested(baseSpiffeIDFromCSR)
	if err != nil {
		return response, err
	}

	var attestResponse *nodeattestor.AttestResponse
	attestResponse, err = no.attestation.Attest(request.AttestedData, attestedBefore)
	if err != nil {
		return response, err
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
	var signCsrResponse *ca.SignCsrResponse
	if signCsrResponse, err = no.ca.SignCsr(&ca.SignCsrRequest{Csr:request.Csr}); err != nil {
		return response, err
	}

	baseSpiffeID := attestResponse.BaseSPIFFEID
	if attestedBefore {
		//UPDATE attested node entry
		if err = no.attestation.UpdateEntry(baseSpiffeID, signCsrResponse.SignedCertificate); err != nil {
			return response, err
		}

	} else {
		//CREATE attested node entry
		if err = no.attestation.CreateEntry(request.AttestedData.Type, baseSpiffeID, signCsrResponse.SignedCertificate); err != nil {
			return response, err
		}
	}

	//Call node resolver plugin to get a map of {Spiffe ID,[ ]Selector}
	var selectors map[string]*common.Selectors
	if selectors, err = no.identity.Resolve([]string{baseSpiffeID}); err != nil {
		return response, err
	}

	if err = no.identity.CreateEntry(baseSpiffeID, selectors[baseSpiffeID].Entries[0]); err != nil {
		return response, err
	}

	svids := make(map[string]*pb.Svid)
	svids[baseSpiffeID] = &pb.Svid{SvidCert: signCsrResponse.SignedCertificate, Ttl: no.baseSpiffeIDTTL}
	registrationEntry := &common.RegistrationEntry{
		SpiffeId:  baseSpiffeID,
		Selectors: selectors[baseSpiffeID].Entries,
	}
	svidUpdate := &pb.SvidUpdate{
		Svids:               svids,
		RegistrationEntries: []*common.RegistrationEntry{registrationEntry},
	}
	response = pb.FetchBaseSVIDResponse{SvidUpdate: svidUpdate}

	return response, nil
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
