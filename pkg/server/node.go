package server

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"reflect"
	"sort"
	"strings"
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
	l           logrus.FieldLogger
	catalog     catalog.Catalog
	trustDomain url.URL
	baseSVIDTtl int32
}

//FetchBaseSVID attests the node and gets the base node SVID.
func (s *nodeServer) FetchBaseSVID(
	ctx context.Context, request *node.FetchBaseSVIDRequest) (
	response *node.FetchBaseSVIDResponse, err error) {

	serverCA := s.catalog.CAs()[0]

	baseSpiffeIDFromCSR, err := getSpiffeIDFromCSR(request.Csr)
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to get SpiffeId from CSR")
	}

	attestedBefore, err := s.isAttested(baseSpiffeIDFromCSR)
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to check if attested")
	}

	// Join token is a special case
	var attestResponse *nodeattestor.AttestResponse
	if request.AttestedData.Type == "join_token" {
		attestResponse, err = s.attestToken(request.AttestedData, attestedBefore)
	} else {
		attestResponse, err = s.attest(request.AttestedData, attestedBefore)
	}
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to attest")
	}

	err = s.validateAttestation(baseSpiffeIDFromCSR, attestResponse)
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to validate attestation")
	}

	signResponse, err := serverCA.SignCsr(&ca.SignCsrRequest{Csr: request.Csr, Ttl: s.baseSVIDTtl})
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to sign CSR")
	}

	if attestedBefore {
		err = s.updateAttestationEntry(signResponse.SignedCertificate, baseSpiffeIDFromCSR)
		if err != nil {
			s.l.Error(err)
			return response, errors.New("Error trying to update attestation entry")
		}

	} else {
		err = s.createAttestationEntry(signResponse.SignedCertificate, baseSpiffeIDFromCSR, request.AttestedData.Type)
		if err != nil {
			s.l.Error(err)
			return response, errors.New("Error trying to create attestation entry")
		}

	}

	selectors, err := s.resolveSelectors(baseSpiffeIDFromCSR)
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to get selectors for baseSpiffeID")
	}

	response, err = s.getFetchBaseSVIDResponse(
		baseSpiffeIDFromCSR, signResponse.SignedCertificate, selectors)
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to compose response")
	}

	s.l.Info("Received node attestation request from ", baseSpiffeIDFromCSR,
		" using strategy '", request.AttestedData.Type,
		"' completed successfully. SVID issued with TTL=", s.baseSVIDTtl)

	return response, nil
}

//FetchSVID gets Workload, Agent certs and CA trust bundles.
//Also used for rotation Base Node SVID or the Registered Node SVID used for this call.
//List can be empty to allow Node Agent cache refresh).
func (s *nodeServer) FetchSVID(server node.Node_FetchSVIDServer) (err error) {

	for {
		request, err := server.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		peerCert, err := s.getCertFromCtx(server.Context())
		if err != nil {
			s.l.Error(err)
			return errors.New("An SVID is required for this request")
		}

		uriNames, err := uri.GetURINamesFromCertificate(peerCert)
		if err != nil {
			s.l.Error(err)
			return errors.New("An SPIFFE ID is required for this request")
		}
		ctxSpiffeID := uriNames[0]

		selectors, err := s.getStoredSelectors(ctxSpiffeID)
		if err != nil {
			s.l.Error(err)
			return errors.New("Error trying to get stored selectors")
		}

		regEntries, err := s.fetchRegistrationEntries(selectors, ctxSpiffeID)
		if err != nil {
			s.l.Error(err)
			return errors.New("Error trying to get registration entries")
		}

		svids, err := s.signCSRs(peerCert, request.Csrs, regEntries)
		if err != nil {
			s.l.Error(err)
			return errors.New("Error trying sign CSRs")
		}

		server.Send(&node.FetchSVIDResponse{
			SvidUpdate: &node.SvidUpdate{
				Svids:               svids,
				RegistrationEntries: regEntries,
			},
		})
	}
}

//TODO
func (s *nodeServer) FetchCPBundle(
	ctx context.Context, request *node.FetchCPBundleRequest) (
	response *node.FetchCPBundleResponse, err error) {
	return response, nil
}

//TODO
func (s *nodeServer) FetchFederatedBundle(
	ctx context.Context, request *node.FetchFederatedBundleRequest) (
	response *node.FetchFederatedBundleResponse, err error) {
	return response, nil
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

func (s *nodeServer) isAttested(baseSpiffeID string) (bool, error) {

	dataStore := s.catalog.DataStores()[0]

	fetchRequest := &datastore.FetchAttestedNodeEntryRequest{
		BaseSpiffeId: baseSpiffeID,
	}
	fetchResponse, err := dataStore.FetchAttestedNodeEntry(fetchRequest)
	if err != nil {
		return false, err
	}

	attestedEntry := fetchResponse.AttestedNodeEntry
	if attestedEntry != nil && attestedEntry.BaseSpiffeId == baseSpiffeID {
		return true, nil
	}

	return false, nil
}

func (s *nodeServer) attest(
	attestedData *common.AttestedData, attestedBefore bool) (
	response *nodeattestor.AttestResponse, err error) {

	// Pick the right node attestor
	var nodeAttestor nodeattestor.NodeAttestor
	for _, a := range s.catalog.NodeAttestors() {
		mp := s.catalog.Find(a)
		if mp.Config.PluginName == attestedData.Type {
			nodeAttestor = a
			break
		}
	}

	if nodeAttestor == nil {
		return nil, fmt.Errorf("could not find node attestor type %s", attestedData.Type)
	}

	attestRequest := &nodeattestor.AttestRequest{
		AttestedData:   attestedData,
		AttestedBefore: attestedBefore,
	}
	attestResponse, err := nodeAttestor.Attest(attestRequest)
	if err != nil {
		return nil, err
	}

	return attestResponse, nil
}

func (s *nodeServer) attestToken(
	attestedData *common.AttestedData, attestedBefore bool) (
	response *nodeattestor.AttestResponse, err error) {

	if attestedBefore {
		return nil, errors.New("join token has already been used")
	}

	ds := s.catalog.DataStores()[0]
	req := &datastore.JoinToken{Token: string(attestedData.Data)}
	t, err := ds.FetchToken(req)
	if err != nil {
		return nil, err
	}

	if t.Token == "" {
		return nil, errors.New("invalid join token")
	}

	if time.Unix(t.Expiry, 0).Before(time.Now()) {
		// Don't fail if we can't delete
		_, _ = ds.DeleteToken(req)
		return nil, errors.New("join token expired")
	}

	// If we're here, the token is valid
	// Don't fail if we can't delete
	_, _ = ds.DeleteToken(req)
	id := &url.URL{
		Scheme: s.trustDomain.Scheme,
		Host:   s.trustDomain.Host,
		Path:   path.Join("spire", "agent", "join_token", t.Token),
	}
	resp := &nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: id.String(),
	}

	return resp, nil
}

func (s *nodeServer) validateAttestation(
	csrBaseSpiffeID string, attestResponse *nodeattestor.AttestResponse) error {

	if !attestResponse.Valid {
		return errors.New("Invalid")
	}
	//check if baseSPIFFEID in attest response matches with SPIFFEID in CSR
	if attestResponse.BaseSPIFFEID != csrBaseSpiffeID {
		return errors.New("BaseSPIFFEID Mismatch")
	}

	return nil
}

func (s *nodeServer) updateAttestationEntry(
	certificate []byte, baseSPIFFEID string) error {

	dataStore := s.catalog.DataStores()[0]

	cert, err := x509.ParseCertificate(certificate)
	if err != nil {
		return err
	}

	updateRequest := &datastore.UpdateAttestedNodeEntryRequest{
		BaseSpiffeId:       baseSPIFFEID,
		CertExpirationDate: cert.NotAfter.Format(time.RFC1123Z),
		CertSerialNumber:   cert.SerialNumber.String(),
	}

	_, err = dataStore.UpdateAttestedNodeEntry(updateRequest)
	if err != nil {
		return err
	}

	return nil
}

func (s *nodeServer) createAttestationEntry(
	certificate []byte, baseSPIFFEID string, attestationType string) error {

	dataStore := s.catalog.DataStores()[0]

	cert, err := x509.ParseCertificate(certificate)
	if err != nil {
		return err
	}

	createRequest := &datastore.CreateAttestedNodeEntryRequest{
		AttestedNodeEntry: &datastore.AttestedNodeEntry{
			AttestedDataType:   attestationType,
			BaseSpiffeId:       baseSPIFFEID,
			CertExpirationDate: cert.NotAfter.Format(time.RFC1123Z),
			CertSerialNumber:   cert.SerialNumber.String(),
		}}
	_, err = dataStore.CreateAttestedNodeEntry(createRequest)
	if err != nil {
		return err
	}

	return nil
}

func (s *nodeServer) resolveSelectors(
	baseSpiffeID string) ([]*common.Selector, error) {

	dataStore := s.catalog.DataStores()[0]
	nodeResolver := s.catalog.NodeResolvers()[0]
	//Call node resolver plugin to get a map of spiffeID=>Selector
	selectors, err := nodeResolver.Resolve([]string{baseSpiffeID})
	if err != nil {
		return nil, err
	}

	baseSelectors, ok := selectors[baseSpiffeID]
	if ok {
		// TODO: Fix complexity
		for _, selector := range baseSelectors.Entries {
			mapEntryRequest := &datastore.CreateNodeResolverMapEntryRequest{
				NodeResolverMapEntry: &datastore.NodeResolverMapEntry{
					BaseSpiffeId: baseSpiffeID,
					Selector:     selector,
				},
			}
			_, err = dataStore.CreateNodeResolverMapEntry(mapEntryRequest)
			if err != nil {
				return nil, err
			}
		}
		return baseSelectors.Entries, nil
	}

	return []*common.Selector{}, nil
}

func (s *nodeServer) getStoredSelectors(
	baseSpiffeID string) ([]*common.Selector, error) {

	dataStore := s.catalog.DataStores()[0]

	req := &datastore.FetchNodeResolverMapEntryRequest{BaseSpiffeId: baseSpiffeID}
	nodeResolutionResponse, err := dataStore.FetchNodeResolverMapEntry(req)
	if err != nil {
		return nil, err
	}

	var selectors []*common.Selector
	for _, item := range nodeResolutionResponse.NodeResolverMapEntryList {
		selectors = append(selectors, item.Selector)
	}

	return selectors, nil
}

func (s *nodeServer) getFetchBaseSVIDResponse(
	baseSpiffeID string, baseSvid []byte, selectors []*common.Selector) (
	*node.FetchBaseSVIDResponse, error) {

	svids := make(map[string]*node.Svid)
	svids[baseSpiffeID] = &node.Svid{
		SvidCert: baseSvid,
		Ttl:      s.baseSVIDTtl,
	}

	regEntries, err := s.fetchRegistrationEntries(selectors, baseSpiffeID)
	if err != nil {
		return nil, err
	}
	svidUpdate := &node.SvidUpdate{
		Svids:               svids,
		RegistrationEntries: regEntries,
	}
	return &node.FetchBaseSVIDResponse{SvidUpdate: svidUpdate}, nil
}

func (s *nodeServer) getCertFromCtx(ctx context.Context) (certificate *x509.Certificate, err error) {

	ctxPeer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, errors.New("It was not posible to extract peer from request")
	}
	tlsInfo, ok := ctxPeer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, errors.New("It was not posible to extract AuthInfo from request")
	}

	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, errors.New("PeerCertificates was empty")
	}

	return tlsInfo.State.PeerCertificates[0], nil
}

func (s *nodeServer) signCSRs(
	peerCert *x509.Certificate, csrs [][]byte, regEntries []*common.RegistrationEntry) (
	svids map[string]*node.Svid, err error) {

	uriNames, err := uri.GetURINamesFromCertificate(peerCert)
	if err != nil {
		s.l.Error(err)
		return nil, errors.New("An SPIFFE ID is required for this request")
	}
	callerID := uriNames[0]

	//convert registration entries into a map for easy lookup
	regEntriesMap := make(map[string]*common.RegistrationEntry)
	for _, entry := range regEntries {
		regEntriesMap[entry.SpiffeId] = entry
	}

	dataStore := s.catalog.DataStores()[0]
	svids = make(map[string]*node.Svid)
	//iterate the CSRs and sign them
	for _, csr := range csrs {
		spiffeID, err := getSpiffeIDFromCSR(csr)
		if err != nil {
			return nil, err
		}

		baseSpiffeIDPrefix := fmt.Sprintf("%s/spire/agent", s.trustDomain.String())

		if spiffeID == callerID && strings.HasPrefix(callerID, baseSpiffeIDPrefix) {
			res, err := dataStore.FetchAttestedNodeEntry(
				&datastore.FetchAttestedNodeEntryRequest{BaseSpiffeId: spiffeID},
			)
			if err != nil {
				return nil, err
			}
			if res.AttestedNodeEntry.CertSerialNumber != peerCert.SerialNumber.String() {
				err := errors.New("SVID serial number does not match")
				return nil, err
			}

			svid, err := s.buildBaseSVID(csr)
			if err != nil {
				return nil, err
			}
			svids[spiffeID] = svid

			s.updateAttestationEntry(svid.SvidCert, spiffeID)
			if err != nil {
				return nil, err
			}

		} else {
			svid, err := s.buildSVID(spiffeID, regEntriesMap, csr)
			if err != nil {
				return nil, err
			}
			svids[spiffeID] = svid
		}
	}

	return svids, nil
}

func (s *nodeServer) buildSVID(
	spiffeID string, regEntries map[string]*common.RegistrationEntry, csr []byte) (
	*node.Svid, error) {

	serverCA := s.catalog.CAs()[0]
	//TODO: Validate that other fields are not populated https://github.com/spiffe/spire/issues/161
	//validate that is present in the registration entries, otherwise we shouldn't sign
	entry, ok := regEntries[spiffeID]
	if !ok {
		err := errors.New("Not entitled to sign CSR")
		return nil, err
	}

	signReq := &ca.SignCsrRequest{Csr: csr, Ttl: entry.Ttl}
	signResponse, err := serverCA.SignCsr(signReq)
	if err != nil {
		return nil, err
	}
	return &node.Svid{SvidCert: signResponse.SignedCertificate, Ttl: entry.Ttl}, nil
}

func (s *nodeServer) buildBaseSVID(csr []byte) (*node.Svid, error) {
	serverCA := s.catalog.CAs()[0]
	signReq := &ca.SignCsrRequest{Csr: csr, Ttl: s.baseSVIDTtl}
	signResponse, err := serverCA.SignCsr(signReq)
	if err != nil {
		return nil, err
	}

	return &node.Svid{
		SvidCert: signResponse.SignedCertificate, Ttl: s.baseSVIDTtl,
	}, nil
}

//TODO: put this into go-spiffe uri?
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
