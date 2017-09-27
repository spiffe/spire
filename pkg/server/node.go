package server

import (
	"crypto/x509"
	"errors"
	"reflect"
	"sort"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/uri"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type nodeServer struct {
	l               logrus.FieldLogger
	catalog         catalog.Catalog
	baseSpiffeIDTTL int32
}

//FetchBaseSVID attests the node and gets the base node SVID.
func (s *nodeServer) FetchBaseSVID(
	ctx context.Context, request *node.FetchBaseSVIDRequest) (
	response *node.FetchBaseSVIDResponse, err error) {

	dataStore := s.catalog.DataStores()[0]
	serverCA := s.catalog.CAs()[0]
	nodeAttestor := s.catalog.NodeAttestors()[0]
	nodeResolver := s.catalog.NodeResolvers()[0]
	//Attest the node and get baseSpiffeID
	//TODO: add GetURINamesFromCSR to go-spiffe/uri
	baseSpiffeIDFromCSR, err := getSpiffeIDFromCSR(request.Csr)
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to get SpiffeId from CSR")
	}

	attestedBefore := false
	fetchRequest := &datastore.FetchAttestedNodeEntryRequest{
		BaseSpiffeId: baseSpiffeIDFromCSR,
	}
	fetchResponse, err := dataStore.FetchAttestedNodeEntry(fetchRequest)
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to verify if attested")
	}

	attestedEntry := fetchResponse.AttestedNodeEntry
	if attestedEntry != nil && attestedEntry.BaseSpiffeId == baseSpiffeIDFromCSR {
		attestedBefore = true
	}

	attestRequest := &nodeattestor.AttestRequest{
		AttestedData:   request.AttestedData,
		AttestedBefore: attestedBefore,
	}
	attestResponse, err := nodeAttestor.Attest(attestRequest)
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
	signResponse, err := serverCA.SignCsr(&ca.SignCsrRequest{Csr: request.Csr})
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to SignCsr")
	}

	//parse csr
	cert, err := x509.ParseCertificate(signResponse.SignedCertificate)
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to parse csr")
	}

	baseSpiffeID := attestResponse.BaseSPIFFEID
	if attestedBefore {
		//UPDATE attested node entry
		updateRequest := &datastore.UpdateAttestedNodeEntryRequest{
			BaseSpiffeId:       baseSpiffeID,
			CertExpirationDate: cert.NotAfter.Format(time.RFC1123Z),
			CertSerialNumber:   cert.SerialNumber.String(),
		}

		_, err := dataStore.UpdateAttestedNodeEntry(updateRequest)
		if err != nil {
			s.l.Error(err)
			return response, errors.New("Error trying to update attestation entry")
		}

	} else {
		//CREATE attested node entry
		createRequest := &datastore.CreateAttestedNodeEntryRequest{AttestedNodeEntry: &datastore.AttestedNodeEntry{
			AttestedDataType:   request.AttestedData.Type,
			BaseSpiffeId:       baseSpiffeID,
			CertExpirationDate: cert.NotAfter.Format(time.RFC1123Z),
			CertSerialNumber:   cert.SerialNumber.String(),
		}}
		_, err := dataStore.CreateAttestedNodeEntry(createRequest)
		if err != nil {
			s.l.Error(err)
			return response, errors.New("Error trying to create attestation entry")
		}
	}

	//Call node resolver plugin to get a map of spiffeID=>Selector
	selectors, err := nodeResolver.Resolve([]string{baseSpiffeID})
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to resolve selectors for baseSpiffeID")
	}

	baseIDSelectors, ok := selectors[baseSpiffeID]
	var selectorEntries []*common.Selector
	if ok {
		// TODO: Fix complexity
		for _, selector := range baseIDSelectors.Entries {
			mapEntryRequest := &datastore.CreateNodeResolverMapEntryRequest{
				NodeResolverMapEntry: &datastore.NodeResolverMapEntry{
					BaseSpiffeId: baseSpiffeID,
					Selector:     selector,
				},
			}
			_, err = dataStore.CreateNodeResolverMapEntry(mapEntryRequest)
			if err != nil {
				s.l.Error(err)
				return response, err
			}
		}
	}

	svids := make(map[string]*node.Svid)
	svids[baseSpiffeID] = &node.Svid{
		SvidCert: signResponse.SignedCertificate,
		Ttl:      s.baseSpiffeIDTTL,
	}

	regEntries, err := s.fetchRegistrationEntries(selectorEntries, baseSpiffeID)
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to fetchRegistrationEntries")
	}
	svidUpdate := &node.SvidUpdate{
		Svids:               svids,
		RegistrationEntries: regEntries,
	}
	response = &node.FetchBaseSVIDResponse{SvidUpdate: svidUpdate}

	return response, nil
}

//FetchSVID gets Workload, Agent certs and CA trust bundles.
//Also used for rotation Base Node SVID or the Registered Node SVID used for this call.
//List can be empty to allow Node Agent cache refresh).
func (s *nodeServer) FetchSVID(
	ctx context.Context, request *node.FetchSVIDRequest) (
	response *node.FetchSVIDResponse, err error) {

	dataStore := s.catalog.DataStores()[0]
	serverCA := s.catalog.CAs()[0]

	var baseSpiffeID string
	ctxPeer, _ := peer.FromContext(ctx)
	tlsInfo, ok := ctxPeer.AuthInfo.(credentials.TLSInfo)
	if ok {
		spiffeID, err := uri.GetURINamesFromCertificate(tlsInfo.State.PeerCertificates[0])
		if err != nil {
			return response, err
		}
		baseSpiffeID = spiffeID[0]
	}

	req := &datastore.FetchNodeResolverMapEntryRequest{BaseSpiffeId: baseSpiffeID}
	nodeResolutionResponse, err := dataStore.FetchNodeResolverMapEntry(req)
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
	svids := make(map[string]*node.Svid)
	for _, csr := range request.Csrs {
		spiffeID, err := getSpiffeIDFromCSR(csr)
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
		res, err := serverCA.SignCsr(signReq)
		if err != nil {
			s.l.Error(err)
			return response, errors.New("Error trying to sign CSR")
		}
		svids[spiffeID] = &node.Svid{SvidCert: res.SignedCertificate, Ttl: entry.Ttl}
	}

	response = &node.FetchSVIDResponse{
		SvidUpdate: &node.SvidUpdate{
			Svids:               svids,
			RegistrationEntries: regEntries,
		},
	}

	return response, nil
}

// Implement the business logic of FetchCPBundle
func (s *nodeServer) FetchCPBundle(
	ctx context.Context, request *node.FetchCPBundleRequest) (
	response *node.FetchCPBundleResponse, err error) {
	return response, nil
}

// Implement the business logic of FetchFederatedBundle
func (s *nodeServer) FetchFederatedBundle(
	ctx context.Context, request *node.FetchFederatedBundleRequest) (
	response *node.FetchFederatedBundleResponse, err error) {
	return response, nil
}

func convertToSelectors(resolution []*datastore.NodeResolverMapEntry) []*common.Selector {
	var selectors []*common.Selector
	for _, item := range resolution {
		selectors = append(selectors, item.Selector)
	}
	return selectors
}

func (s *nodeServer) fetchRegistrationEntries(selectors []*common.Selector, spiffeID string) (
	[]*common.RegistrationEntry, error) {

	dataStore := s.catalog.DataStores()[0]

	///lookup Registration Entries for resolved selectors
	var entries []*common.RegistrationEntry
	var selectorsEntries []*common.RegistrationEntry

	set := selector.NewSet(selectors)
	reqs := []*datastore.ListSelectorEntriesRequest{}
	for subset := range set.Power() {
		reqs = append(reqs, &datastore.ListSelectorEntriesRequest{Selectors: subset.Raw()})
	}
	for _, req := range reqs {
		listSelectorResponse, err := dataStore.ListSelectorEntries(req)
		if err != nil {
			return nil, err
		}
		selectorsEntries = append(selectorsEntries, listSelectorResponse.RegisteredEntryList...)
	}
	entries = append(entries, selectorsEntries...)

	///lookup Registration Entries where spiffeID is the parent ID
	listResponse, err := dataStore.ListParentIDEntries(&datastore.ListParentIDEntriesRequest{ParentId: spiffeID})
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

//TODO: put this into go-spiffe uri
func getSpiffeIDFromCSR(csr []byte) (spiffeID string, err error) {
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
