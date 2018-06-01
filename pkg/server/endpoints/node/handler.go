package node

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/uri"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/spiffe/spire/proto/server/noderesolver"
	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type Handler struct {
	Log         logrus.FieldLogger
	Catalog     catalog.Catalog
	TrustDomain url.URL
}

//FetchBaseSVID attests the node and gets the base node SVID.
func (h *Handler) FetchBaseSVID(
	ctx context.Context, request *node.FetchBaseSVIDRequest) (
	response *node.FetchBaseSVIDResponse, err error) {

	serverCA := h.Catalog.CAs()[0]

	baseSpiffeIDFromCSR, err := getSpiffeIDFromCSR(request.Csr)
	if err != nil {
		h.Log.Error(err)
		return response, errors.New("Error trying to get SpiffeId from CSR")
	}

	attestedBefore, err := h.isAttested(ctx, baseSpiffeIDFromCSR)
	if err != nil {
		h.Log.Error(err)
		return response, errors.New("Error trying to check if attested")
	}

	// Join token is a special case
	var attestResponse *nodeattestor.AttestResponse
	if request.AttestedData.Type == "join_token" {
		attestResponse, err = h.attestToken(ctx, request.AttestedData, attestedBefore)
	} else {
		attestResponse, err = h.attest(ctx, request.AttestedData, attestedBefore)
	}
	if err != nil {
		h.Log.Error(err)
		return response, errors.New("Error trying to attest")
	}

	err = h.validateAttestation(baseSpiffeIDFromCSR, attestResponse)
	if err != nil {
		h.Log.Error(err)
		return response, errors.New("Error trying to validate attestation")
	}

	h.Log.Debugf("Signing CSR for Agent SVID %v", baseSpiffeIDFromCSR)
	signResponse, err := serverCA.SignCsr(ctx, &ca.SignCsrRequest{Csr: request.Csr})
	if err != nil {
		h.Log.Error(err)
		return response, errors.New("Error trying to sign CSR")
	}

	if attestedBefore {
		err = h.updateAttestationEntry(ctx, signResponse.SignedCertificate, baseSpiffeIDFromCSR)
		if err != nil {
			h.Log.Error(err)
			return response, errors.New("Error trying to update attestation entry")
		}

	} else {
		err = h.createAttestationEntry(ctx, signResponse.SignedCertificate, baseSpiffeIDFromCSR, request.AttestedData.Type)
		if err != nil {
			h.Log.Error(err)
			return response, errors.New("Error trying to create attestation entry")
		}

	}

	if err := h.updateNodeResolverMap(ctx, baseSpiffeIDFromCSR); err != nil {
		h.Log.Error(err)
		return response, errors.New("Error trying to get selectors for baseSpiffeID")
	}

	response, err = h.getFetchBaseSVIDResponse(ctx,
		baseSpiffeIDFromCSR, signResponse.SignedCertificate)
	if err != nil {
		h.Log.Error(err)
		return response, errors.New("Error trying to compose response")
	}

	p, ok := peer.FromContext(ctx)
	if ok {
		h.Log.Infof("Node attestation request from %v completed using strategy %v", p.Addr, request.AttestedData.Type)
	}

	return response, nil
}

//FetchSVID gets Workload, Agent certs and CA trust bundles.
//Also used for rotation Base Node SVID or the Registered Node SVID used for this call.
//List can be empty to allow Node Agent cache refresh).
func (h *Handler) FetchSVID(server node.Node_FetchSVIDServer) (err error) {
	for {
		request, err := server.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		ctx := server.Context()

		peerCert, err := h.getCertFromCtx(ctx)
		if err != nil {
			h.Log.Error(err)
			return errors.New("An SVID is required for this request")
		}

		uriNames, err := uri.GetURINamesFromCertificate(peerCert)
		if err != nil {
			h.Log.Error(err)
			return errors.New("An SPIFFE ID is required for this request")
		}
		ctxSpiffeID := uriNames[0]

		regEntries, err := FetchRegistrationEntries(ctx, h.Catalog.DataStores()[0], ctxSpiffeID)
		if err != nil {
			h.Log.Error(err)
			return errors.New("Error trying to get registration entries")
		}

		svids, err := h.signCSRs(ctx, peerCert, request.Csrs, regEntries)
		if err != nil {
			h.Log.Error(err)
			return errors.New("Error trying sign CSRs")
		}

		bundle, err := h.getBundle(ctx)
		if err != nil {
			h.Log.Errorf("Error retreiving bundle from datastore: %v", err)
			return fmt.Errorf("Error retreiving bundle")
		}

		err = server.Send(&node.FetchSVIDResponse{
			SvidUpdate: &node.SvidUpdate{
				Svids:               svids,
				Bundle:              bundle,
				RegistrationEntries: regEntries,
			},
		})
		if err != nil {
			h.Log.Errorf("Error sending FetchSVIDResponse: %v", err)
		}
	}
}

//TODO
func (h *Handler) FetchFederatedBundle(
	ctx context.Context, request *node.FetchFederatedBundleRequest) (
	response *node.FetchFederatedBundleResponse, err error) {
	return response, nil
}

func (h *Handler) isAttested(ctx context.Context, baseSpiffeID string) (bool, error) {

	dataStore := h.Catalog.DataStores()[0]

	fetchRequest := &datastore.FetchAttestedNodeEntryRequest{
		BaseSpiffeId: baseSpiffeID,
	}
	fetchResponse, err := dataStore.FetchAttestedNodeEntry(ctx, fetchRequest)
	if err != nil {
		return false, err
	}

	attestedEntry := fetchResponse.AttestedNodeEntry
	if attestedEntry != nil && attestedEntry.BaseSpiffeId == baseSpiffeID {
		return true, nil
	}

	return false, nil
}

func (h *Handler) attest(ctx context.Context,
	attestedData *common.AttestedData, attestedBefore bool) (
	response *nodeattestor.AttestResponse, err error) {

	// Pick the right node attestor
	var nodeAttestor nodeattestor.NodeAttestor
	for _, a := range h.Catalog.NodeAttestors() {
		mp := h.Catalog.Find(a)
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
	attestResponse, err := nodeAttestor.Attest(ctx, attestRequest)
	if err != nil {
		return nil, err
	}

	return attestResponse, nil
}

func (h *Handler) attestToken(ctx context.Context,
	attestedData *common.AttestedData, attestedBefore bool) (
	response *nodeattestor.AttestResponse, err error) {

	if attestedBefore {
		return nil, errors.New("join token has already been used")
	}

	ds := h.Catalog.DataStores()[0]
	req := &datastore.JoinToken{Token: string(attestedData.Data)}
	t, err := ds.FetchToken(ctx, req)
	if err != nil {
		return nil, err
	}

	if t.Token == "" {
		return nil, errors.New("invalid join token")
	}

	if time.Unix(t.Expiry, 0).Before(time.Now()) {
		// Don't fail if we can't delete
		_, _ = ds.DeleteToken(ctx, req)
		return nil, errors.New("join token expired")
	}

	// If we're here, the token is valid
	// Don't fail if we can't delete
	_, _ = ds.DeleteToken(ctx, req)
	id := &url.URL{
		Scheme: h.TrustDomain.Scheme,
		Host:   h.TrustDomain.Host,
		Path:   path.Join("spire", "agent", "join_token", t.Token),
	}
	resp := &nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: id.String(),
	}

	return resp, nil
}

func (h *Handler) validateAttestation(
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

func (h *Handler) updateAttestationEntry(ctx context.Context,
	certificate []byte, baseSPIFFEID string) error {

	dataStore := h.Catalog.DataStores()[0]

	cert, err := x509.ParseCertificate(certificate)
	if err != nil {
		return err
	}

	updateRequest := &datastore.UpdateAttestedNodeEntryRequest{
		BaseSpiffeId:       baseSPIFFEID,
		CertExpirationDate: cert.NotAfter.Format(time.RFC1123Z),
		CertSerialNumber:   cert.SerialNumber.String(),
	}

	_, err = dataStore.UpdateAttestedNodeEntry(ctx, updateRequest)
	if err != nil {
		return err
	}

	return nil
}

func (h *Handler) createAttestationEntry(ctx context.Context,
	certificate []byte, baseSPIFFEID string, attestationType string) error {

	dataStore := h.Catalog.DataStores()[0]

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
	_, err = dataStore.CreateAttestedNodeEntry(ctx, createRequest)
	if err != nil {
		return err
	}

	return nil
}

func (h *Handler) updateNodeResolverMap(ctx context.Context,
	baseSpiffeID string) error {

	dataStore := h.Catalog.DataStores()[0]
	nodeResolver := h.Catalog.NodeResolvers()[0]
	//Call node resolver plugin to get a map of spiffeID=>Selector
	response, err := nodeResolver.Resolve(ctx, &noderesolver.ResolveRequest{
		BaseSpiffeIdList: []string{baseSpiffeID},
	})
	if err != nil {
		return err
	}

	if selectors, ok := response.Map[baseSpiffeID]; ok {
		// TODO: Fix complexity
		for _, selector := range selectors.Entries {
			mapEntryRequest := &datastore.CreateNodeResolverMapEntryRequest{
				NodeResolverMapEntry: &datastore.NodeResolverMapEntry{
					BaseSpiffeId: baseSpiffeID,
					Selector:     selector,
				},
			}
			_, err = dataStore.CreateNodeResolverMapEntry(ctx, mapEntryRequest)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *Handler) getStoredSelectors(ctx context.Context,
	baseSpiffeID string) ([]*common.Selector, error) {

	dataStore := h.Catalog.DataStores()[0]

	req := &datastore.FetchNodeResolverMapEntryRequest{BaseSpiffeId: baseSpiffeID}
	nodeResolutionResponse, err := dataStore.FetchNodeResolverMapEntry(ctx, req)
	if err != nil {
		return nil, err
	}

	var selectors []*common.Selector
	for _, item := range nodeResolutionResponse.NodeResolverMapEntryList {
		selectors = append(selectors, item.Selector)
	}

	return selectors, nil
}

func (h *Handler) getFetchBaseSVIDResponse(ctx context.Context,
	baseSpiffeID string, baseSvid []byte) (
	*node.FetchBaseSVIDResponse, error) {

	// Parse base svid to approximate TTL
	cert, err := x509.ParseCertificate(baseSvid)
	if err != nil {
		return &node.FetchBaseSVIDResponse{}, err
	}

	svids := make(map[string]*node.Svid)
	svids[baseSpiffeID] = &node.Svid{
		SvidCert: cert.Raw,
		Ttl:      int32(time.Until(cert.NotAfter).Seconds()),
	}

	regEntries, err := FetchRegistrationEntries(ctx, h.Catalog.DataStores()[0], baseSpiffeID)
	if err != nil {
		return nil, err
	}

	bundle, err := h.getBundle(ctx)
	if err != nil {
		return nil, err
	}

	svidUpdate := &node.SvidUpdate{
		Svids:               svids,
		Bundle:              bundle,
		RegistrationEntries: regEntries,
	}
	return &node.FetchBaseSVIDResponse{SvidUpdate: svidUpdate}, nil
}

func (h *Handler) getCertFromCtx(ctx context.Context) (certificate *x509.Certificate, err error) {

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

func (h *Handler) signCSRs(ctx context.Context,
	peerCert *x509.Certificate, csrs [][]byte, regEntries []*common.RegistrationEntry) (
	svids map[string]*node.Svid, err error) {

	uriNames, err := uri.GetURINamesFromCertificate(peerCert)
	if err != nil {
		h.Log.Error(err)
		return nil, errors.New("An SPIFFE ID is required for this request")
	}
	callerID := uriNames[0]

	//convert registration entries into a map for easy lookup
	regEntriesMap := make(map[string]*common.RegistrationEntry)
	for _, entry := range regEntries {
		regEntriesMap[entry.SpiffeId] = entry
	}

	dataStore := h.Catalog.DataStores()[0]
	svids = make(map[string]*node.Svid)
	//iterate the CSRs and sign them
	for _, csr := range csrs {
		spiffeID, err := getSpiffeIDFromCSR(csr)
		if err != nil {
			return nil, err
		}

		baseSpiffeIDPrefix := fmt.Sprintf("%s/spire/agent", h.TrustDomain.String())

		if spiffeID == callerID && strings.HasPrefix(callerID, baseSpiffeIDPrefix) {
			res, err := dataStore.FetchAttestedNodeEntry(ctx,
				&datastore.FetchAttestedNodeEntryRequest{BaseSpiffeId: spiffeID},
			)
			if err != nil {
				return nil, err
			}
			if res.AttestedNodeEntry.CertSerialNumber != peerCert.SerialNumber.String() {
				err := errors.New("SVID serial number does not match")
				return nil, err
			}

			h.Log.Debugf("Signing SVID for %v on request by %v", spiffeID, callerID)
			svid, err := h.buildBaseSVID(ctx, csr)
			if err != nil {
				return nil, err
			}
			svids[spiffeID] = svid

			h.updateAttestationEntry(ctx, svid.SvidCert, spiffeID)
			if err != nil {
				return nil, err
			}

		} else {
			h.Log.Debugf("Signing SVID for %v on request by %v", spiffeID, callerID)
			svid, err := h.buildSVID(ctx, spiffeID, regEntriesMap, csr)
			if err != nil {
				return nil, err
			}
			svids[spiffeID] = svid
		}
	}

	return svids, nil
}

func (h *Handler) buildSVID(ctx context.Context,
	spiffeID string, regEntries map[string]*common.RegistrationEntry, csr []byte) (
	*node.Svid, error) {

	serverCA := h.Catalog.CAs()[0]
	//TODO: Validate that other fields are not populated https://github.com/spiffe/spire/issues/161
	//validate that is present in the registration entries, otherwise we shouldn't sign
	entry, ok := regEntries[spiffeID]
	if !ok {
		err := errors.New("Not entitled to sign CSR")
		return nil, err
	}

	signReq := &ca.SignCsrRequest{Csr: csr, Ttl: entry.Ttl}
	signResponse, err := serverCA.SignCsr(ctx, signReq)
	if err != nil {
		return nil, err
	}
	return &node.Svid{SvidCert: signResponse.SignedCertificate, Ttl: entry.Ttl}, nil
}

func (h *Handler) buildBaseSVID(ctx context.Context, csr []byte) (*node.Svid, error) {
	serverCA := h.Catalog.CAs()[0]
	signReq := &ca.SignCsrRequest{Csr: csr}
	signResponse, err := serverCA.SignCsr(ctx, signReq)
	if err != nil {
		return nil, err
	}

	// Parse base SVID to approximate TTL
	cert, err := x509.ParseCertificate(signResponse.SignedCertificate)
	if err != nil {
		return nil, err
	}

	return &node.Svid{
		SvidCert: signResponse.SignedCertificate,
		Ttl:      int32(time.Until(cert.NotAfter).Seconds()),
	}, nil
}

// getBundle fetches the current CA bundle from the datastore.
func (h *Handler) getBundle(ctx context.Context) ([]byte, error) {
	ds := h.Catalog.DataStores()[0]
	req := &datastore.Bundle{
		TrustDomain: h.TrustDomain.String(),
	}
	b, err := ds.FetchBundle(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("get bundle from datastore: %v", err)
	}

	return b.CaCerts, nil
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

func FetchRegistrationEntries(ctx context.Context,
	dataStore datastore.DataStore, spiffeID string) (
	entries []*common.RegistrationEntry, err error) {

	fetcher := newRegistrationEntryFetcher(dataStore)
	return fetcher.Fetch(ctx, spiffeID)
}

type registrationEntryFetcher struct {
	dataStore datastore.DataStore
}

func newRegistrationEntryFetcher(dataStore datastore.DataStore) *registrationEntryFetcher {
	return &registrationEntryFetcher{
		dataStore: dataStore,
	}
}

func (f *registrationEntryFetcher) Fetch(ctx context.Context, id string) ([]*common.RegistrationEntry, error) {
	entries, err := f.fetch(ctx, id, make(map[string]bool))
	if err != nil {
		return nil, err
	}
	return util.DedupRegistrationEntries(entries), nil
}

func (f *registrationEntryFetcher) fetch(ctx context.Context, id string, visited map[string]bool) ([]*common.RegistrationEntry, error) {
	if visited[id] {
		return nil, nil
	}
	visited[id] = true

	directEntries, err := f.directEntries(ctx, id)
	if err != nil {
		return nil, err
	}

	entries := directEntries
	for _, directEntry := range directEntries {
		descendantEntries, err := f.fetch(ctx, directEntry.SpiffeId, visited)
		if err != nil {
			return nil, err
		}
		entries = append(entries, descendantEntries...)
	}

	return entries, nil
}

// directEntries queries the datastore to determine the registration entries
// the provided ID is immediately authorized to issue.
func (f *registrationEntryFetcher) directEntries(ctx context.Context, id string) ([]*common.RegistrationEntry, error) {
	childEntries, err := f.childEntries(ctx, id)
	if err != nil {
		return nil, err
	}

	mappedEntries, err := f.mappedEntries(ctx, id)
	if err != nil {
		return nil, err
	}

	return append(childEntries, mappedEntries...), nil
}

// childEntries returns all registration entries for which the given ID is
// defined as a parent.
func (f *registrationEntryFetcher) childEntries(ctx context.Context, clientID string) ([]*common.RegistrationEntry, error) {
	resp, err := f.dataStore.ListParentIDEntries(ctx,
		&datastore.ListParentIDEntriesRequest{
			ParentId: clientID,
		})
	if err != nil {
		return nil, err
	}

	return resp.RegisteredEntryList, nil
}

// mappedEntries returns all registration entries for which the given ID has
// been mapped to by a node resolver.
func (f *registrationEntryFetcher) mappedEntries(ctx context.Context, clientID string) ([]*common.RegistrationEntry, error) {
	resolveResp, err := f.dataStore.FetchNodeResolverMapEntry(ctx,
		&datastore.FetchNodeResolverMapEntryRequest{
			BaseSpiffeId: clientID,
		})
	if err != nil {
		return nil, err
	}

	selectors := []*common.Selector{}
	for _, entry := range resolveResp.NodeResolverMapEntryList {
		selectors = append(selectors, entry.Selector)
	}

	// No need to look for more entries if we didn't get any selectors
	if len(selectors) < 1 {
		return nil, nil
	}

	listResp, err := f.dataStore.ListMatchingEntries(ctx,
		&datastore.ListSelectorEntriesRequest{
			Selectors: selectors,
		})
	if err != nil {
		return nil, err
	}

	return listResp.RegisteredEntryList, nil
}
