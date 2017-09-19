package node

import (
	"context"
	"errors"

	"reflect"
	"sort"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/uri"
	pb "github.com/spiffe/spire/pkg/api/node"
	"github.com/spiffe/spire/pkg/common"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/nodeattestor"
	"github.com/spiffe/spire/services"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// Service is the interface that provides node api methods.
type Service interface {
	FetchBaseSVID(ctx context.Context, request pb.FetchBaseSVIDRequest) (response pb.FetchBaseSVIDResponse, err error)
	FetchSVID(ctx context.Context, request pb.FetchSVIDRequest) (response pb.FetchSVIDResponse, err error)
	FetchCPBundle(ctx context.Context, request pb.FetchCPBundleRequest) (response pb.FetchCPBundleResponse, err error)
	FetchFederatedBundle(ctx context.Context, request pb.FetchFederatedBundleRequest) (response pb.FetchFederatedBundleResponse, err error)
}

type service struct {
	l               logrus.FieldLogger
	attestation     services.Attestation
	identity        services.Identity
	ca              services.CA
	baseSpiffeIDTTL int32
	dataStore       datastore.DataStore
	serverCA        ca.ControlPlaneCa
}

//Config is a configuration struct to init the service
type Config struct {
	Logger          logrus.FieldLogger
	Attestation     services.Attestation
	Identity        services.Identity
	CA              services.CA
	DataStore       datastore.DataStore
	ServerCA        ca.ControlPlaneCa
	BaseSpiffeIDTTL int32
}

// NewService creates a node service with the necessary dependencies.
func NewService(config Config) (s Service) {
	//TODO: validate config?
	return &service{
		l:               config.Logger,
		attestation:     config.Attestation,
		identity:        config.Identity,
		ca:              config.CA,
		baseSpiffeIDTTL: config.BaseSpiffeIDTTL,
		dataStore:       config.DataStore,
		serverCA:        config.ServerCA,
	}
}

//FetchBaseSVID attests the node and gets the base node SVID.
func (s *service) FetchBaseSVID(ctx context.Context, request pb.FetchBaseSVIDRequest) (response pb.FetchBaseSVIDResponse, err error) {
	//Attest the node and get baseSpiffeID
	baseSpiffeIDFromCSR, err := s.ca.GetSpiffeIDFromCSR(request.Csr)
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to get SpiffeId from CSR")
	}

	attestedBefore, err := s.attestation.IsAttested(baseSpiffeIDFromCSR)
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to verify if attested")
	}

	var attestResponse *nodeattestor.AttestResponse
	attestResponse, err = s.attestation.Attest(request.AttestedData, attestedBefore)
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to attest")
	}

	//Validate
	if !attestResponse.Valid {
		err := errors.New("Invalid")
		s.l.Error(err)
		return response, err
	}

	//check if baseSPIFFEID in attest response matches with SPIFFEID in CSR
	if attestResponse.BaseSPIFFEID != baseSpiffeIDFromCSR {
		err := errors.New("BaseSPIFFEID MisMatch")
		s.l.Error(err)
		return response, err
	}

	//Sign csr
	var signCsrResponse *ca.SignCsrResponse
	if signCsrResponse, err = s.ca.SignCsr(&ca.SignCsrRequest{Csr: request.Csr}); err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to SignCsr")
	}

	baseSpiffeID := attestResponse.BaseSPIFFEID
	if attestedBefore {
		//UPDATE attested node entry
		if err = s.attestation.UpdateEntry(baseSpiffeID, signCsrResponse.SignedCertificate); err != nil {
			s.l.Error(err)
			return response, errors.New("Error trying to update attestation entry")
		}

	} else {
		//CREATE attested node entry
		if err = s.attestation.CreateEntry(request.AttestedData.Type, baseSpiffeID, signCsrResponse.SignedCertificate); err != nil {
			s.l.Error(err)
			return response, errors.New("Error trying to create attestation entry")
		}
	}

	//Call node resolver plugin to get a map of {Spiffe ID,[ ]Selector}
	var selectors map[string]*common.Selectors
	if selectors, err = s.identity.Resolve([]string{baseSpiffeID}); err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to resolve selectors for baseSpiffeID")
	}

	baseIDSelectors, ok := selectors[baseSpiffeID]
	//generateCombination(baseIDSelectors) (TODO:walmav)
	var selectorEntries []*common.Selector
	if ok {
		selectorEntries = baseIDSelectors.Entries
		for _, selector := range selectorEntries {
			if err = s.identity.CreateEntry(baseSpiffeID, selector); err != nil {
				s.l.Error(err)
				return response, errors.New("Error trying to create node resolution entry")
			}
		}
	}

	svids := make(map[string]*pb.Svid)
	svids[baseSpiffeID] = &pb.Svid{SvidCert: signCsrResponse.SignedCertificate, Ttl: s.baseSpiffeIDTTL}

	regEntries, err := s.fetchRegistrationEntries(selectorEntries, baseSpiffeID)
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to fetchRegistrationEntries")
	}
	svidUpdate := &pb.SvidUpdate{
		Svids:               svids,
		RegistrationEntries: regEntries,
	}
	response = pb.FetchBaseSVIDResponse{SvidUpdate: svidUpdate}

	return response, nil
}

//FetchSVID gets Workload, Agent certs and CA trust bundles.
//Also used for rotation Base Node SVID or the Registered Node SVID used for this call.
//List can be empty to allow Node Agent cache refresh).
func (s *service) FetchSVID(ctx context.Context, request pb.FetchSVIDRequest) (response pb.FetchSVIDResponse, err error) {
	//TODO: extract this from the caller cert
	var baseSpiffeID string
	ctxPeer, _ := peer.FromContext(ctx)
	tlsInfo, ok := ctxPeer.AuthInfo.(credentials.TLSInfo)
	if ok {
		spiffeID, err := uri.GetURINamesFromCertificate(tlsInfo.State.PeerCertificates[0])
		if err != nil {
			return response,err
		}
		baseSpiffeID = spiffeID[0]
	}

	req := &datastore.FetchNodeResolverMapEntryRequest{BaseSpiffeId: baseSpiffeID}
	nodeResolutionResponse, err := s.dataStore.FetchNodeResolverMapEntry(req)
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to FetchNodeResolverMapEntry")
	}
	selectors := convertToSelectors(nodeResolutionResponse.NodeResolverMapEntryList)

	regEntries, err := s.fetchRegistrationEntries(selectors, baseSpiffeID)
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to fetchRegistrationEntries")
	}

	//convert registration entries to map for easy lookup
	regEntriesMap := make(map[string]*common.RegistrationEntry)
	for _, entry := range regEntries {
		regEntriesMap[entry.SpiffeId] = entry
	}

	//iterate CSRs, validate them and sign the certificates
	svids := make(map[string]*pb.Svid)
	for _, csr := range request.Csrs {
		spiffeID, err := s.ca.GetSpiffeIDFromCSR(csr)
		if err != nil {
			s.l.Error(err)
			return response, errors.New("Error trying to get SpiffeId from CSR")
		}

		//TODO: Validate that other fields are not populated https://github.com/spiffe/spire/issues/161
		//validate that is present in the registration entries, otherwise we shouldn't sign
		entry, ok := regEntriesMap[spiffeID]
		if !ok {
			err := errors.New("Not entitled to sign CSR")
			s.l.Error(err)
			return response, err
		}

		//sign
		signReq := &ca.SignCsrRequest{Csr: csr}
		res, err := s.serverCA.SignCsr(signReq)
		if err != nil {
			s.l.Error(err)
			return response, errors.New("Error trying to sign CSR")
		}
		svids[spiffeID] = &pb.Svid{SvidCert: res.SignedCertificate, Ttl: entry.Ttl}
	}

	response.SvidUpdate = &pb.SvidUpdate{
		Svids:               svids,
		RegistrationEntries: regEntries,
	}
	return response, nil
}

// Implement the business logic of FetchCPBundle
func (s *service) FetchCPBundle(ctx context.Context, request pb.FetchCPBundleRequest) (response pb.FetchCPBundleResponse, err error) {
	return response, nil
}

// Implement the business logic of FetchFederatedBundle
func (s *service) FetchFederatedBundle(ctx context.Context, request pb.FetchFederatedBundleRequest) (response pb.FetchFederatedBundleResponse, err error) {
	return response, nil
}

func convertToSelectors(resolution []*datastore.NodeResolverMapEntry) []*common.Selector {
	var selectors []*common.Selector
	for _, item := range resolution {
		selectors = append(selectors, item.Selector)
	}
	return selectors
}

func (s *service) fetchRegistrationEntries(selectors []*common.Selector, spiffeID string) (
	[]*common.RegistrationEntry, error) {
	///lookup Registration Entries for resolved selectors
	var entries []*common.RegistrationEntry
	var selectorsEntries []*common.RegistrationEntry

	for _, selector := range selectors {
		listSelectorResponse, err := s.dataStore.ListSelectorEntries(&datastore.ListSelectorEntriesRequest{Selector: selector})
		if err != nil {
			return nil, err
		}
		selectorsEntries = append(selectorsEntries, listSelectorResponse.RegisteredEntryList...)
	}
	entries = append(entries, selectorsEntries...)

	///lookup Registration Entries where spiffeID is the parent ID
	listResponse, err := s.dataStore.ListParentIDEntries(&datastore.ListParentIDEntriesRequest{ParentId: spiffeID})
	if err != nil {
		return nil, err
	}
	///append parentEntries
	for _, entry := range listResponse.RegisteredEntryList {
		exists := false
		sort.Slice(entry.Selectors, util.SelectorsSortFunction(entry.Selectors))
		for _, oldEntry := range selectorsEntries {
			sort.Slice(oldEntry.Selectors, util.SelectorsSortFunction(oldEntry.Selectors))
			if reflect.DeepEqual(entry, oldEntry) {
				exists = true
			}
		}
		if !exists {
			entries = append(entries, entry)
		}
	}
	return entries, err
}
