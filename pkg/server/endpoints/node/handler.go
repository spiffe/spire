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
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/util/regentryutil"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/spiffe/spire/proto/server/noderesolver"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type HandlerConfig struct {
	Log         logrus.FieldLogger
	Metrics     telemetry.Metrics
	Catalog     catalog.Catalog
	ServerCA    ca.ServerCA
	TrustDomain url.URL
}

type Handler struct {
	c       HandlerConfig
	limiter Limiter

	// test hooks
	hooks struct {
		now func() time.Time
	}
}

func NewHandler(config HandlerConfig) *Handler {
	h := &Handler{
		c:       config,
		limiter: NewLimiter(config.Log),
	}
	h.hooks.now = time.Now
	return h
}

//Attest attests the node and gets the base node SVID.
func (h *Handler) Attest(stream node.Node_AttestServer) (err error) {
	counter := telemetry.StartCall(h.c.Metrics, "node_api", "attest")
	defer counter.Done(&err)

	// make sure node attestor stream will be cancelled if things go awry
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	// pull off the initial request
	request, err := stream.Recv()
	if err != nil {
		return err
	}

	err = h.limiter.Limit(ctx, AttestMsg, 1)
	if err != nil {
		return status.Error(codes.ResourceExhausted, err.Error())
	}

	baseSpiffeIDFromCSR, err := getSpiffeIDFromCSR(request.Csr)
	if err != nil {
		h.c.Log.Error(err)
		return errors.New("Error trying to get SpiffeId from CSR")
	}

	counter.AddLabel("spiffe_id", baseSpiffeIDFromCSR)

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
	svid, err := h.c.ServerCA.SignX509SVID(ctx, request.Csr, 0)
	if err != nil {
		h.c.Log.Error(err)
		return errors.New("Error trying to sign CSR")
	}

	if err := h.updateNodeSelectors(ctx, baseSpiffeIDFromCSR, attestResponse, request.AttestationData.Type); err != nil {
		h.c.Log.Error(err)
		return errors.New("Error trying to get selectors for baseSpiffeID")
	}

	response, err := h.getAttestResponse(ctx, baseSpiffeIDFromCSR, svid)
	if err != nil {
		h.c.Log.Error(err)
		return errors.New("Error trying to compose response")
	}

	if attestedBefore {
		err = h.updateAttestationEntry(ctx, svid[0], baseSpiffeIDFromCSR)
		if err != nil {
			h.c.Log.Error(err)
			return errors.New("Error trying to update attestation entry")
		}
	} else {
		err = h.createAttestationEntry(ctx, svid[0], baseSpiffeIDFromCSR, request.AttestationData.Type)
		if err != nil {
			h.c.Log.Error(err)
			return errors.New("Error trying to create attestation entry")
		}
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
	counter := telemetry.StartCall(h.c.Metrics, "node_api", "x509_svid", "fetch")
	defer counter.Done(&err)

	peerCert, ok := getPeerCertificate(server.Context())
	if !ok {
		return errors.New("client SVID is required for this request")
	}

	for {
		request, err := server.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		ctx := server.Context()

		err = h.limiter.Limit(ctx, CSRMsg, len(request.Csrs))
		if err != nil {
			return status.Error(codes.ResourceExhausted, err.Error())
		}

		agentID, err := getSpiffeIDFromCert(peerCert)
		if err != nil {
			h.c.Log.Error(err)
			return err
		}

		regEntries, err := regentryutil.FetchRegistrationEntries(ctx, h.c.Catalog.DataStores()[0], agentID)
		if err != nil {
			h.c.Log.Error(err)
			return errors.New("Error trying to get registration entries")
		}

		svids, err := h.signCSRs(ctx, peerCert, request.Csrs, regEntries)
		if err != nil {
			h.c.Log.Error(err)
			return errors.New("Error trying sign CSRs")
		}

		bundles, err := h.getBundlesForEntries(ctx, regEntries)
		if err != nil {
			h.c.Log.Error(err)
			return err
		}

		for spiffeID := range svids {
			counter.AddLabel("spiffe_id", spiffeID)
		}

		// TODO: remove in 0.8, along with deprecated fields
		ourBundle := bundles[h.c.TrustDomain.String()]

		err = server.Send(&node.FetchX509SVIDResponse{
			SvidUpdate: &node.X509SVIDUpdate{
				Svids:               svids,
				DEPRECATEDBundle:    makeDeprecatedBundle(ourBundle).CaCerts,
				RegistrationEntries: regEntries,
				DEPRECATEDBundles:   makeDeprecatedBundles(bundles),
				Bundles:             bundles,
			},
		})
		if err != nil {
			h.c.Log.Errorf("Error sending FetchX509SVIDResponse: %v", err)
		}
	}
}

func (h *Handler) FetchJWTSVID(ctx context.Context, req *node.FetchJWTSVIDRequest) (resp *node.FetchJWTSVIDResponse, err error) {
	counter := telemetry.StartCall(h.c.Metrics, "node_api", "jwt_svid", "fetch")
	defer counter.Done(&err)

	if err := h.limiter.Limit(ctx, JSRMsg, 1); err != nil {
		return nil, status.Error(codes.ResourceExhausted, err.Error())
	}

	peerCert, ok := getPeerCertificate(ctx)
	if !ok {
		return nil, errors.New("client SVID is required for this request")
	}

	// validate request parameters
	switch {
	case req.Jsr == nil:
		return nil, errors.New("request missing JSR")
	case req.Jsr.SpiffeId == "":
		return nil, errors.New("request missing SPIFFE ID")
	case len(req.Jsr.Audience) == 0:
		return nil, errors.New("request missing audience")
	}

	counter.AddLabel("spiffe_id", req.Jsr.SpiffeId)

	agentID, err := getSpiffeIDFromCert(peerCert)
	if err != nil {
		h.c.Log.Error(err)
		return nil, err
	}

	dataStore := h.c.Catalog.DataStores()[0]
	regEntries, err := regentryutil.FetchRegistrationEntries(ctx, dataStore, agentID)
	if err != nil {
		return nil, err
	}

	if agentID != req.Jsr.SpiffeId {
		found := false
		for _, candidateEntry := range regEntries {
			if candidateEntry.SpiffeId == req.Jsr.SpiffeId {
				found = true
				break
			}
		}
		if !found {
			err := fmt.Errorf("caller %q is not authorized for %q", agentID, req.Jsr.SpiffeId)
			h.c.Log.Error(err)
			return nil, err
		}
	}

	token, err := h.c.ServerCA.SignJWTSVID(ctx, req.Jsr)
	if err != nil {
		h.c.Log.Error(err)
		return nil, err
	}

	issuedAt, expiresAt, err := jwtsvid.GetTokenExpiry(token)
	if err != nil {
		return nil, err
	}

	for _, audience := range req.Jsr.Audience {
		counter.AddLabel("audience", audience)
	}

	return &node.FetchJWTSVIDResponse{
		Svid: &node.JWTSVID{
			Token:     token,
			IssuedAt:  issuedAt.Unix(),
			ExpiresAt: expiresAt.Unix(),
		},
	}, nil
}

func (h *Handler) AuthorizeCall(ctx context.Context, fullMethod string) (context.Context, error) {
	switch fullMethod {
	// no authn/authz is required for attestation
	case "/spire.api.node.Node/Attest":

	// peer certificate required for SVID fetching
	case "/spire.api.node.Node/FetchX509SVID",
		"/spire.api.node.Node/FetchJWTSVID":
		peerCert, err := getPeerCertificateFromRequestContext(ctx)
		if err != nil {
			h.c.Log.Error(err)
			return nil, errors.New("client SVID is required for this request")
		}
		ctx = withPeerCertificate(ctx, peerCert)

	// method not handled
	default:
		return nil, status.Errorf(codes.PermissionDenied, "authorization not implemented for method %q", fullMethod)
	}

	return ctx, nil
}

func (h *Handler) isAttested(ctx context.Context, baseSpiffeID string) (bool, error) {

	dataStore := h.c.Catalog.DataStores()[0]

	fetchRequest := &datastore.FetchAttestedNodeRequest{
		SpiffeId: baseSpiffeID,
	}
	fetchResponse, err := dataStore.FetchAttestedNode(ctx, fetchRequest)
	if err != nil {
		return false, err
	}

	node := fetchResponse.Node
	if node != nil && node.SpiffeId == baseSpiffeID {
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
			return nil, fmt.Errorf("Error trying to attest: %v", err)
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

	tokenValue := string(attestationData.Data)

	ds := h.c.Catalog.DataStores()[0]
	resp, err := ds.FetchJoinToken(ctx, &datastore.FetchJoinTokenRequest{
		Token: tokenValue,
	})
	if err != nil {
		return nil, err
	}
	if resp.JoinToken == nil {
		return nil, errors.New("no such token")
	}
	t := resp.JoinToken

	if t.Token == "" {
		return nil, errors.New("invalid join token")
	}

	_, err = ds.DeleteJoinToken(ctx, &datastore.DeleteJoinTokenRequest{
		Token: tokenValue,
	})
	if err != nil {
		return nil, err
	}

	if time.Unix(t.Expiry, 0).Before(h.hooks.now()) {
		return nil, errors.New("join token expired")
	}

	// If we're here, the token is valid
	id := &url.URL{
		Scheme: h.c.TrustDomain.Scheme,
		Host:   h.c.TrustDomain.Host,
		Path:   path.Join("spire", "agent", "join_token", t.Token),
	}
	return &nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: id.String(),
	}, nil
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

	updateRequest := &datastore.UpdateAttestedNodeRequest{
		SpiffeId:         baseSPIFFEID,
		CertNotAfter:     cert.NotAfter.Unix(),
		CertSerialNumber: cert.SerialNumber.String(),
	}

	if _, err := dataStore.UpdateAttestedNode(ctx, updateRequest); err != nil {
		return err
	}

	return nil
}

func (h *Handler) createAttestationEntry(ctx context.Context,
	cert *x509.Certificate, baseSPIFFEID string, attestationType string) error {

	dataStore := h.c.Catalog.DataStores()[0]

	createRequest := &datastore.CreateAttestedNodeRequest{
		Node: &datastore.AttestedNode{
			AttestationDataType: attestationType,
			SpiffeId:            baseSPIFFEID,
			CertNotAfter:        cert.NotAfter.Unix(),
			CertSerialNumber:    cert.SerialNumber.String(),
		}}
	if _, err := dataStore.CreateAttestedNode(ctx, createRequest); err != nil {
		return err
	}

	return nil
}

func (h *Handler) updateNodeSelectors(ctx context.Context,
	baseSpiffeID string, attestResponse *nodeattestor.AttestResponse, attestationType string) error {

	// Select node resolver based on request attestation type
	var nodeResolver noderesolver.NodeResolver
	for _, r := range h.c.Catalog.NodeResolvers() {
		if r.Config().PluginName == attestationType {
			nodeResolver = r
			break
		}
	}

	var selectors []*common.Selector
	if nodeResolver == nil {
		// If not matching node resolver found, skip adding additional selectors
		h.c.Log.Debug("could not find node resolver type %q", attestationType)
	} else {
		//Call node resolver plugin to get a map of spiffeID=>Selector
		response, err := nodeResolver.Resolve(ctx, &noderesolver.ResolveRequest{
			BaseSpiffeIdList: []string{baseSpiffeID},
		})
		if err != nil {
			return err
		}

		if resolved := response.Map[baseSpiffeID]; resolved != nil {
			selectors = append(selectors, resolved.Entries...)
		}
	}

	selectors = append(selectors, attestResponse.Selectors...)

	dataStore := h.c.Catalog.DataStores()[0]
	_, err := dataStore.SetNodeSelectors(ctx, &datastore.SetNodeSelectorsRequest{
		Selectors: &datastore.NodeSelectors{
			SpiffeId:  baseSpiffeID,
			Selectors: selectors,
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func (h *Handler) getAttestResponse(ctx context.Context,
	baseSpiffeID string, svid []*x509.Certificate) (
	*node.AttestResponse, error) {

	svids := make(map[string]*node.X509SVID)
	svids[baseSpiffeID] = makeX509SVID(svid)

	regEntries, err := regentryutil.FetchRegistrationEntries(ctx, h.c.Catalog.DataStores()[0], baseSpiffeID)
	if err != nil {
		return nil, err
	}

	bundles, err := h.getBundlesForEntries(ctx, regEntries)
	if err != nil {
		return nil, err
	}

	// TODO: remove in 0.8, along with deprecated fields
	ourBundle := bundles[h.c.TrustDomain.String()]

	svidUpdate := &node.X509SVIDUpdate{
		Svids:               svids,
		DEPRECATEDBundle:    makeDeprecatedBundle(ourBundle).CaCerts,
		RegistrationEntries: regEntries,
		DEPRECATEDBundles:   makeDeprecatedBundles(bundles),
		Bundles:             bundles,
	}
	return &node.AttestResponse{SvidUpdate: svidUpdate}, nil
}

func (h *Handler) signCSRs(ctx context.Context,
	peerCert *x509.Certificate, csrs [][]byte, regEntries []*common.RegistrationEntry) (
	svids map[string]*node.X509SVID, err error) {

	callerID, err := getSpiffeIDFromCert(peerCert)
	if err != nil {
		return nil, err
	}

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
			res, err := dataStore.FetchAttestedNode(ctx,
				&datastore.FetchAttestedNodeRequest{SpiffeId: spiffeID},
			)
			if err != nil {
				return nil, err
			}
			if res.Node.CertSerialNumber != peerCert.SerialNumber.String() {
				err := errors.New("SVID serial number does not match")
				return nil, err
			}

			h.c.Log.Debugf("Signing SVID for %v on request by %v", spiffeID, callerID)
			svid, svidCert, err := h.buildBaseSVID(ctx, csr)
			if err != nil {
				return nil, err
			}
			svids[spiffeID] = svid

			if err := h.updateAttestationEntry(ctx, svidCert, spiffeID); err != nil {
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

	svid, err := h.c.ServerCA.SignX509SVID(ctx, csr, time.Duration(entry.Ttl)*time.Second)
	if err != nil {
		return nil, err
	}
	return makeX509SVID(svid), nil
}

func (h *Handler) buildBaseSVID(ctx context.Context, csr []byte) (*node.X509SVID, *x509.Certificate, error) {
	svid, err := h.c.ServerCA.SignX509SVID(ctx, csr, 0)
	if err != nil {
		return nil, nil, err
	}

	return makeX509SVID(svid), svid[0], nil
}

func (h *Handler) getBundlesForEntries(ctx context.Context, regEntries []*common.RegistrationEntry) (map[string]*common.Bundle, error) {
	bundles := make(map[string]*common.Bundle)

	ourBundle, err := h.getBundle(ctx, h.c.TrustDomain.String())
	if err != nil {
		return nil, err
	}
	bundles[ourBundle.TrustDomainId] = ourBundle

	for _, entry := range regEntries {
		for _, trustDomainId := range entry.FederatesWith {
			if bundles[trustDomainId] != nil {
				continue
			}
			bundle, err := h.getBundle(ctx, trustDomainId)
			if err != nil {
				return nil, err
			}
			bundles[trustDomainId] = bundle
		}
	}
	return bundles, nil
}

// getBundle fetches a bundle from the datastore, by trust domain
func (h *Handler) getBundle(ctx context.Context, trustDomainId string) (*common.Bundle, error) {
	ds := h.c.Catalog.DataStores()[0]

	resp, err := ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: trustDomainId,
	})
	if err != nil {
		return nil, fmt.Errorf("get bundle from datastore: %v", err)
	}
	if resp.Bundle == nil {
		return nil, errors.New("bundle not found")
	}
	return resp.Bundle, nil
}

func getPeerCertificateFromRequestContext(ctx context.Context) (cert *x509.Certificate, err error) {
	ctxPeer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, errors.New("no peer information")
	}
	tlsInfo, ok := ctxPeer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, errors.New("no TLS auth info for peer")
	}

	if len(tlsInfo.State.VerifiedChains) == 0 {
		return nil, errors.New("no verified client certificate presented by peer")
	}
	chain := tlsInfo.State.VerifiedChains[0]
	if len(chain) == 0 {
		// this shouldn't be possible with the tls package, but we should be
		// defensive.
		return nil, errors.New("verified client chain is missing certificates")
	}

	return chain[0], nil
}

func makeDeprecatedBundle(b *common.Bundle) *node.Bundle {
	return &node.Bundle{
		Id:      b.TrustDomainId,
		CaCerts: bundleutil.RootCAsDERFromBundleProto(b),
	}
}

func makeDeprecatedBundles(bs map[string]*common.Bundle) map[string]*node.Bundle {
	out := make(map[string]*node.Bundle)
	for k, v := range bs {
		out[k] = makeDeprecatedBundle(v)
	}
	return out
}

func getSpiffeIDFromCSR(csrBytes []byte) (string, error) {
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return "", err
	}
	if len(csr.URIs) != 1 {
		return "", errors.New("The CSR must have exactly one URI SAN")
	}

	spiffeID, err := idutil.NormalizeSpiffeIDURL(csr.URIs[0], idutil.AllowAny())
	if err != nil {
		return "", err
	}
	return spiffeID.String(), nil
}

func getSpiffeIDFromCert(cert *x509.Certificate) (string, error) {
	if len(cert.URIs) == 0 {
		return "", errors.New("No URI SANs in certificate")
	}
	spiffeID, err := idutil.NormalizeSpiffeIDURL(cert.URIs[0], idutil.AllowAny())
	if err != nil {
		return "", err
	}
	return spiffeID.String(), nil
}

func makeX509SVID(svid []*x509.Certificate) *node.X509SVID {
	var certChain []byte
	// The svid slice contains all of the certificates back to the signing
	// root. We only want to return the SVID and intermediates necessary to
	// chain back to the root, so skip the last element.
	for _, cert := range svid[:len(svid)-1] {
		certChain = append(certChain, cert.Raw...)
	}
	return &node.X509SVID{
		DEPRECATEDCert: svid[0].Raw,
		CertChain:      certChain,
		ExpiresAt:      svid[0].NotAfter.Unix(),
	}
}

type peerCertificateKey struct{}

func withPeerCertificate(ctx context.Context, peerCert *x509.Certificate) context.Context {
	return context.WithValue(ctx, peerCertificateKey{}, peerCert)
}

func getPeerCertificate(ctx context.Context) (*x509.Certificate, bool) {
	peerCert, ok := ctx.Value(peerCertificateKey{}).(*x509.Certificate)
	return peerCert, ok
}
