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
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/util/regentryutil"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/spiffe/spire/proto/server/noderesolver"
	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type HandlerConfig struct {
	Log         logrus.FieldLogger
	Catalog     catalog.Catalog
	ServerCA    ca.ServerCA
	TrustDomain url.URL
}

type Handler struct {
	c HandlerConfig

	// test hooks
	hooks struct {
		now func() time.Time
	}
}

func NewHandler(config HandlerConfig) *Handler {
	h := &Handler{
		c: config,
	}
	h.hooks.now = time.Now
	return h
}

//Attest attests the node and gets the base node SVID.
func (h *Handler) Attest(stream node.Node_AttestServer) (err error) {
	// make sure node attestor stream will be cancelled if things go awry
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	// pull off the initial request
	request, err := stream.Recv()
	if err != nil {
		return err
	}

	baseSpiffeIDFromCSR, err := getSpiffeIDFromCSR(request.Csr)
	if err != nil {
		h.c.Log.Error(err)
		return errors.New("Error trying to get SpiffeId from CSR")
	}

	attestedBefore, err := h.isAttested(ctx, baseSpiffeIDFromCSR)
	if err != nil {
		h.c.Log.Error(err)
		return errors.New("Error trying to check if attested")
	}

	// Pick the right node attestor
	var attestStream nodeattestor.Attest_Stream
	if request.AttestationData.Type != "join_token" {
		var nodeAttestor nodeattestor.NodeAttestor
		for _, a := range h.c.Catalog.NodeAttestors() {
			if a.Config().PluginName == request.AttestationData.Type {
				nodeAttestor = a
				break
			}
		}
		if nodeAttestor == nil {
			return fmt.Errorf("could not find node attestor type %s", request.AttestationData.Type)
		}

		attestStream, err = nodeAttestor.Attest(ctx)
		if err != nil {
			return fmt.Errorf("unable to open attest stream: %v", err)
		}
	}

	attestResponse, err := h.doAttestChallengeResponse(ctx, stream, attestStream, request, attestedBefore)
	if err != nil {
		return err
	}

	if attestStream != nil {
		if err := attestStream.CloseSend(); err != nil {
			return err
		}
		if _, err := attestStream.Recv(); err != io.EOF {
			h.c.Log.Warnf("expected EOF on attestation stream; got %v", err)
		}
	}

	err = h.validateAttestation(baseSpiffeIDFromCSR, attestResponse)
	if err != nil {
		h.c.Log.Error(err)
		return errors.New("Error trying to validate attestation")
	}

	h.c.Log.Debugf("Signing CSR for Agent SVID %v", baseSpiffeIDFromCSR)
	cert, err := h.c.ServerCA.SignX509SVID(ctx, request.Csr, 0)
	if err != nil {
		h.c.Log.Error(err)
		return errors.New("Error trying to sign CSR")
	}

	if attestedBefore {
		err = h.updateAttestationEntry(ctx, cert, baseSpiffeIDFromCSR)
		if err != nil {
			h.c.Log.Error(err)
			return errors.New("Error trying to update attestation entry")
		}

	} else {
		err = h.createAttestationEntry(ctx, cert, baseSpiffeIDFromCSR, request.AttestationData.Type)
		if err != nil {
			h.c.Log.Error(err)
			return errors.New("Error trying to create attestation entry")
		}

	}

	if err := h.updateNodeResolverMap(ctx, baseSpiffeIDFromCSR, attestResponse); err != nil {
		h.c.Log.Error(err)
		return errors.New("Error trying to get selectors for baseSpiffeID")
	}

	response, err := h.getAttestResponse(ctx, baseSpiffeIDFromCSR, cert.Raw)
	if err != nil {
		h.c.Log.Error(err)
		return errors.New("Error trying to compose response")
	}

	p, ok := peer.FromContext(ctx)
	if ok {
		h.c.Log.Infof("Node attestation request from %v completed using strategy %v", p.Addr, request.AttestationData.Type)
	}

	if err := stream.Send(response); err != nil {
		return err
	}

	return nil
}

//FetchX509SVID gets Workload, Agent certs and CA trust bundles.
//Also used for rotation Base Node SVID or the Registered Node SVID used for this call.
//List can be empty to allow Node Agent cache refresh).
func (h *Handler) FetchX509SVID(server node.Node_FetchX509SVIDServer) (err error) {
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
			h.c.Log.Error(err)
			return errors.New("An SVID is required for this request")
		}

		uriNames, err := uri.GetURINamesFromCertificate(peerCert)
		if err != nil {
			h.c.Log.Error(err)
			return errors.New("An SPIFFE ID is required for this request")
		}
		ctxSpiffeID := uriNames[0]

		regEntries, err := regentryutil.FetchRegistrationEntries(ctx, h.c.Catalog.DataStores()[0], ctxSpiffeID)
		if err != nil {
			h.c.Log.Error(err)
			return errors.New("Error trying to get registration entries")
		}

		svids, err := h.signCSRs(ctx, peerCert, request.Csrs, regEntries)
		if err != nil {
			h.c.Log.Error(err)
			return errors.New("Error trying sign CSRs")
		}

		bundle, err := h.getBundle(ctx)
		if err != nil {
			h.c.Log.Errorf("Error retreiving bundle from datastore: %v", err)
			return fmt.Errorf("Error retreiving bundle")
		}

		err = server.Send(&node.FetchX509SVIDResponse{
			SvidUpdate: &node.X509SVIDUpdate{
				Svids:               svids,
				Bundle:              bundle,
				RegistrationEntries: regEntries,
			},
		})
		if err != nil {
			h.c.Log.Errorf("Error sending FetchX509SVIDResponse: %v", err)
		}
	}
}

func (h *Handler) FetchJWTSVID(ctx context.Context, req *node.FetchJWTSVIDRequest) (*node.FetchJWTSVIDResponse, error) {
	return nil, errors.New("not implemented")
}

//TODO
func (h *Handler) FetchFederatedBundle(
	ctx context.Context, request *node.FetchFederatedBundleRequest) (
	response *node.FetchFederatedBundleResponse, err error) {
	return response, nil
}

func (h *Handler) isAttested(ctx context.Context, baseSpiffeID string) (bool, error) {

	dataStore := h.c.Catalog.DataStores()[0]

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

func (h *Handler) doAttestChallengeResponse(ctx context.Context,
	nodeStream node.Node_AttestServer,
	attestStream nodeattestor.Attest_Stream,
	request *node.AttestRequest, attestedBefore bool) (*nodeattestor.AttestResponse, error) {
	// challenge/response loop
	for {
		response, err := h.attest(ctx, attestStream, request, attestedBefore)
		if err != nil {
			h.c.Log.Error(err)
			return nil, errors.New("Error trying to attest")
		}
		if response.Challenge == nil {
			return response, nil
		}

		challengeResponse := &node.AttestResponse{
			Challenge: response.Challenge,
		}

		if err := nodeStream.Send(challengeResponse); err != nil {
			return nil, fmt.Errorf("failed to send challenge request: %v", err)
		}

		request, err = nodeStream.Recv()
		if err != nil {
			return nil, fmt.Errorf("failed to receive challenge response: %v", err)
		}
	}
}

func (h *Handler) attest(ctx context.Context,
	attestStream nodeattestor.Attest_Stream,
	nodeRequest *node.AttestRequest, attestedBefore bool) (
	response *nodeattestor.AttestResponse, err error) {

	if attestStream == nil {
		return h.attestToken(ctx, nodeRequest.AttestationData, attestedBefore)
	}

	attestRequest := &nodeattestor.AttestRequest{
		AttestationData: nodeRequest.AttestationData,
		Response:        nodeRequest.Response,
		AttestedBefore:  attestedBefore,
	}
	if err := attestStream.Send(attestRequest); err != nil {
		return nil, err
	}

	return attestStream.Recv()
}

func (h *Handler) attestToken(ctx context.Context,
	attestationData *common.AttestationData, attestedBefore bool) (
	response *nodeattestor.AttestResponse, err error) {

	if attestedBefore {
		return nil, errors.New("join token has already been used")
	}

	ds := h.c.Catalog.DataStores()[0]
	req := &datastore.JoinToken{Token: string(attestationData.Data)}
	t, err := ds.FetchToken(ctx, req)
	if err != nil {
		return nil, err
	}

	if t.Token == "" {
		return nil, errors.New("invalid join token")
	}

	if time.Unix(t.Expiry, 0).Before(h.hooks.now()) {
		// Don't fail if we can't delete
		_, _ = ds.DeleteToken(ctx, req)
		return nil, errors.New("join token expired")
	}

	// If we're here, the token is valid
	// Don't fail if we can't delete
	_, _ = ds.DeleteToken(ctx, req)
	id := &url.URL{
		Scheme: h.c.TrustDomain.Scheme,
		Host:   h.c.TrustDomain.Host,
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
	cert *x509.Certificate, baseSPIFFEID string) error {

	dataStore := h.c.Catalog.DataStores()[0]

	updateRequest := &datastore.UpdateAttestedNodeEntryRequest{
		BaseSpiffeId:       baseSPIFFEID,
		CertExpirationDate: cert.NotAfter.Format(time.RFC1123Z),
		CertSerialNumber:   cert.SerialNumber.String(),
	}

	if _, err := dataStore.UpdateAttestedNodeEntry(ctx, updateRequest); err != nil {
		return err
	}

	return nil
}

func (h *Handler) createAttestationEntry(ctx context.Context,
	cert *x509.Certificate, baseSPIFFEID string, attestationType string) error {

	dataStore := h.c.Catalog.DataStores()[0]

	createRequest := &datastore.CreateAttestedNodeEntryRequest{
		AttestedNodeEntry: &datastore.AttestedNodeEntry{
			AttestationDataType: attestationType,
			BaseSpiffeId:        baseSPIFFEID,
			CertExpirationDate:  cert.NotAfter.Format(time.RFC1123Z),
			CertSerialNumber:    cert.SerialNumber.String(),
		}}
	if _, err := dataStore.CreateAttestedNodeEntry(ctx, createRequest); err != nil {
		return err
	}

	return nil
}

func (h *Handler) updateNodeResolverMap(ctx context.Context,
	baseSpiffeID string, attestResponse *nodeattestor.AttestResponse) error {

	nodeResolver := h.c.Catalog.NodeResolvers()[0]
	//Call node resolver plugin to get a map of spiffeID=>Selector
	response, err := nodeResolver.Resolve(ctx, &noderesolver.ResolveRequest{
		BaseSpiffeIdList: []string{baseSpiffeID},
	})
	if err != nil {
		return err
	}

	if selectors, ok := response.Map[baseSpiffeID]; ok {
		for _, selector := range selectors.Entries {
			err := h.createNodeResolverMapEntry(ctx, baseSpiffeID, selector)
			if err != nil {
				return err
			}
		}
	}

	for _, selector := range attestResponse.Selectors {
		err := h.createNodeResolverMapEntry(ctx, baseSpiffeID, selector)
		if err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) createNodeResolverMapEntry(ctx context.Context, baseSpiffeID string, selector *common.Selector) error {
	dataStore := h.c.Catalog.DataStores()[0]
	mapEntryRequest := &datastore.CreateNodeResolverMapEntryRequest{
		NodeResolverMapEntry: &datastore.NodeResolverMapEntry{
			BaseSpiffeId: baseSpiffeID,
			Selector:     selector,
		},
	}
	_, err := dataStore.CreateNodeResolverMapEntry(ctx, mapEntryRequest)
	if err != nil {
		return err
	}
	return nil
}

func (h *Handler) getAttestResponse(ctx context.Context,
	baseSpiffeID string, baseSvid []byte) (
	*node.AttestResponse, error) {

	// Parse base svid to approximate TTL
	cert, err := x509.ParseCertificate(baseSvid)
	if err != nil {
		return &node.AttestResponse{}, err
	}

	svids := make(map[string]*node.X509SVID)
	svids[baseSpiffeID] = makeX509SVID(cert)
	regEntries, err := regentryutil.FetchRegistrationEntries(ctx, h.c.Catalog.DataStores()[0], baseSpiffeID)
	if err != nil {
		return nil, err
	}

	bundle, err := h.getBundle(ctx)
	if err != nil {
		return nil, err
	}

	svidUpdate := &node.X509SVIDUpdate{
		Svids:               svids,
		Bundle:              bundle,
		RegistrationEntries: regEntries,
	}
	return &node.AttestResponse{SvidUpdate: svidUpdate}, nil
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
	svids map[string]*node.X509SVID, err error) {

	uriNames, err := uri.GetURINamesFromCertificate(peerCert)
	if err != nil {
		h.c.Log.Error(err)
		return nil, errors.New("An SPIFFE ID is required for this request")
	}
	callerID := uriNames[0]

	//convert registration entries into a map for easy lookup
	regEntriesMap := make(map[string]*common.RegistrationEntry)
	for _, entry := range regEntries {
		regEntriesMap[entry.SpiffeId] = entry
	}

	dataStore := h.c.Catalog.DataStores()[0]
	svids = make(map[string]*node.X509SVID)
	//iterate the CSRs and sign them
	for _, csr := range csrs {
		spiffeID, err := getSpiffeIDFromCSR(csr)
		if err != nil {
			return nil, err
		}

		baseSpiffeIDPrefix := fmt.Sprintf("%s/spire/agent", h.c.TrustDomain.String())

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

			h.c.Log.Debugf("Signing SVID for %v on request by %v", spiffeID, callerID)
			svid, svidCert, err := h.buildBaseSVID(ctx, csr)
			if err != nil {
				return nil, err
			}
			svids[spiffeID] = svid

			h.updateAttestationEntry(ctx, svidCert, spiffeID)
			if err != nil {
				return nil, err
			}

		} else {
			h.c.Log.Debugf("Signing SVID for %v on request by %v", spiffeID, callerID)
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
	*node.X509SVID, error) {

	//TODO: Validate that other fields are not populated https://github.com/spiffe/spire/issues/161
	//validate that is present in the registration entries, otherwise we shouldn't sign
	entry, ok := regEntries[spiffeID]
	if !ok {
		err := errors.New("Not entitled to sign CSR")
		return nil, err
	}

	cert, err := h.c.ServerCA.SignX509SVID(ctx, csr, time.Duration(entry.Ttl)*time.Second)
	if err != nil {
		return nil, err
	}
	return makeX509SVID(cert), nil
}

func (h *Handler) buildBaseSVID(ctx context.Context, csr []byte) (*node.X509SVID, *x509.Certificate, error) {
	cert, err := h.c.ServerCA.SignX509SVID(ctx, csr, 0)
	if err != nil {
		return nil, nil, err
	}

	return makeX509SVID(cert), cert, nil
}

// getBundle fetches the current CA bundle from the datastore.
func (h *Handler) getBundle(ctx context.Context) ([]byte, error) {
	ds := h.c.Catalog.DataStores()[0]
	req := &datastore.Bundle{
		TrustDomain: h.c.TrustDomain.String(),
	}
	b, err := ds.FetchBundle(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("get bundle from datastore: %v", err)
	}

	return b.CaCerts, nil
}

// timeUntil determines how much time until a date. It utilizes the test hook
// so we can get deterministic ttl determination.
func (h *Handler) timeUntil(t time.Time) time.Duration {
	return t.Sub(h.hooks.now())
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

func makeX509SVID(cert *x509.Certificate) *node.X509SVID {
	return &node.X509SVID{
		Cert:      cert.Raw,
		ExpiresAt: cert.NotAfter.Unix(),
	}
}
