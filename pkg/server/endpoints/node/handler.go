package node

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/util/regentryutil"
	"github.com/spiffe/spire/proto/spire/api/node"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/server/datastore"
	"github.com/spiffe/spire/proto/spire/server/nodeattestor"
	"github.com/spiffe/spire/proto/spire/server/noderesolver"
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
	Clock       clock.Clock

	// Allow agentless spiffeIds when doing node attestation
	AllowAgentlessNodeAttestors bool
}

type Handler struct {
	c       HandlerConfig
	limiter Limiter
}

func NewHandler(config HandlerConfig) *Handler {
	if config.Clock == nil {
		config.Clock = clock.New()
	}
	return &Handler{
		c:       config,
		limiter: NewLimiter(config.Log),
	}
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

	if request.AttestationData == nil {
		return status.Error(codes.InvalidArgument, "request missing attestation data")
	}
	if request.AttestationData.Type == "" {
		return status.Error(codes.InvalidArgument, "request missing attestation data type")
	}

	if len(request.Csr) == 0 {
		return status.Error(codes.InvalidArgument, "request missing CSR")
	}

	agentID, err := getSpiffeIDFromCSR(request.Csr, h.getNodeAttestationValidationMode())
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "request CSR is invalid: %v", err)
	}
	counter.AddLabel("spiffe_id", agentID)

	attestedBefore, err := h.isAttested(ctx, agentID)
	if err != nil {
		h.c.Log.Error(err)
		return errors.New("failed to determine if agent has already attested")
	}

	// Pick the right node attestor
	var attestStream nodeattestor.NodeAttestor_AttestClient
	if request.AttestationData.Type != "join_token" {
		nodeAttestor, ok := h.c.Catalog.GetNodeAttestorNamed(request.AttestationData.Type)
		if !ok {
			return fmt.Errorf("could not find node attestor type %q", request.AttestationData.Type)
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

	if err := h.validateAttestation(agentID, attestResponse); err != nil {
		h.c.Log.Error(err)
		return errors.New("attestor returned unexpected response")
	}

	h.c.Log.Debugf("Signing CSR for Agent SVID %v", agentID)
	svid, err := h.c.ServerCA.SignX509SVID(ctx, request.Csr, ca.X509Params{})
	if err != nil {
		h.c.Log.Error(err)
		return errors.New("failed to sign CSR")
	}

	if err := h.updateNodeSelectors(ctx, agentID, attestResponse, request.AttestationData.Type); err != nil {
		h.c.Log.Error(err)
		return errors.New("failed to update node selectors")
	}

	response, err := h.getAttestResponse(ctx, agentID, svid)
	if err != nil {
		h.c.Log.Error(err)
		return errors.New("failed to compose response")
	}

	if attestedBefore {
		err = h.updateAttestationEntry(ctx, svid[0])
		if err != nil {
			h.c.Log.Error(err)
			return errors.New("failed to update attestation entry")
		}
	} else {
		err = h.createAttestationEntry(ctx, svid[0], request.AttestationData.Type)
		if err != nil {
			h.c.Log.Error(err)
			return errors.New("failed to create attestation entry")
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

func (h *Handler) getNodeAttestationValidationMode() idutil.ValidationMode {
	if h.c.AllowAgentlessNodeAttestors {
		return idutil.AllowAnyInTrustDomain(h.c.TrustDomain.Host)
	}
	return idutil.AllowTrustDomainAgent(h.c.TrustDomain.Host)
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

		regEntries, err := regentryutil.FetchRegistrationEntries(ctx, h.c.Catalog.GetDataStore(), agentID)
		if err != nil {
			h.c.Log.Error(err)
			return errors.New("failed to fetch agent registration entries")
		}

		svids, err := h.signCSRs(ctx, peerCert, request.Csrs, regEntries)
		if err != nil {
			h.c.Log.Error(err)
			return errors.New("failed to sign CSRs")
		}

		bundles, err := h.getBundlesForEntries(ctx, regEntries)
		if err != nil {
			h.c.Log.Error(err)
			return err
		}

		for spiffeID := range svids {
			counter.AddLabel("spiffe_id", spiffeID)
		}

		err = server.Send(&node.FetchX509SVIDResponse{
			SvidUpdate: &node.X509SVIDUpdate{
				Svids:               svids,
				RegistrationEntries: regEntries,
				Bundles:             bundles,
			},
		})
		if err != nil {
			h.c.Log.Errorf("Error sending FetchX509SVIDResponse: %v", err)
		}
	}
}

func (h *Handler) FetchX509CASVID(ctx context.Context, req *node.FetchX509CASVIDRequest) (_ *node.FetchX509CASVIDResponse, err error) {
	counter := telemetry.StartCall(h.c.Metrics, "node_api", "x509_ca_svid", "fetch")
	defer counter.Done(&err)

	peerCert, ok := getPeerCertificate(ctx)
	if !ok {
		return nil, errors.New("downstream SVID is required for this request")
	}

	entry, ok := getDownstreamEntry(ctx)
	if !ok {
		return nil, errors.New("downstream entry is required for this request")
	}

	err = h.limiter.Limit(ctx, CSRMsg, 1)
	if err != nil {
		return nil, status.Error(codes.ResourceExhausted, err.Error())
	}

	agentID, err := getSpiffeIDFromCert(peerCert)
	if err != nil {
		h.c.Log.Error(err)
		return nil, err
	}

	sourceAddress := "unknown"
	if peerAddress, ok := getPeerAddress(ctx); ok {
		sourceAddress = peerAddress.String()
	}

	signLog := h.c.Log.WithFields(logrus.Fields{
		"caller_id":      agentID,
		"source_address": sourceAddress,
	})

	signLog.Debug("Signing downstream CA SVID")
	svid, err := h.buildCASVID(ctx, req.Csr, ca.X509Params{
		TTL: time.Duration(entry.Ttl) * time.Second,
	})
	if err != nil {
		return nil, err
	}

	bundle, err := h.getBundle(ctx, h.c.TrustDomain.String())
	if err != nil {
		return nil, err
	}

	return &node.FetchX509CASVIDResponse{
		Svid:   svid,
		Bundle: bundle,
	}, nil
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
		return nil, status.Error(codes.InvalidArgument, "request missing JSR")
	case req.Jsr.SpiffeId == "":
		return nil, status.Error(codes.InvalidArgument, "request missing SPIFFE ID")
	case len(req.Jsr.Audience) == 0:
		return nil, status.Error(codes.InvalidArgument, "request missing audience")
	}

	counter.AddLabel("spiffe_id", req.Jsr.SpiffeId)

	agentID, err := getSpiffeIDFromCert(peerCert)
	if err != nil {
		h.c.Log.Error(err)
		return nil, err
	}

	ds := h.c.Catalog.GetDataStore()
	regEntries, err := regentryutil.FetchRegistrationEntries(ctx, ds, agentID)
	if err != nil {
		return nil, err
	}

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
			return nil, status.Error(codes.PermissionDenied, "agent SVID is required for this request")
		}

		if err := h.validateAgentSVID(ctx, peerCert); err != nil {
			h.c.Log.Error(err)
			return nil, status.Error(codes.PermissionDenied, "agent is not attested or no longer valid")
		}

		ctx = withPeerCertificate(ctx, peerCert)
	case "/spire.api.node.Node/FetchX509CASVID":
		peerCert, err := getPeerCertificateFromRequestContext(ctx)
		if err != nil {
			h.c.Log.Error(err)
			return nil, status.Error(codes.PermissionDenied, "a downstream SVID is required for this request")
		}
		entry, err := h.validateDownstreamSVID(ctx, peerCert)
		if err != nil {
			h.c.Log.Error(err)
			return nil, status.Error(codes.PermissionDenied, "peer is not a valid downstream SPIRE server")
		}

		ctx = withPeerCertificate(ctx, peerCert)
		ctx = withDownstreamEntry(ctx, entry)
	// method not handled
	default:
		return nil, status.Errorf(codes.PermissionDenied, "authorization not implemented for method %q", fullMethod)
	}

	return ctx, nil
}

func (h *Handler) isAttested(ctx context.Context, baseSpiffeID string) (bool, error) {
	ds := h.c.Catalog.GetDataStore()

	fetchRequest := &datastore.FetchAttestedNodeRequest{
		SpiffeId: baseSpiffeID,
	}
	fetchResponse, err := ds.FetchAttestedNode(ctx, fetchRequest)
	if err != nil {
		return false, err
	}

	node := fetchResponse.Node
	if node != nil && node.SpiffeId == baseSpiffeID {
		return true, nil
	}

	return false, nil
}

func (h *Handler) validateAgentSVID(ctx context.Context, cert *x509.Certificate) error {
	ds := h.c.Catalog.GetDataStore()

	agentID, err := getSpiffeIDFromCert(cert)
	if err != nil {
		return err
	}

	// agent SVIDs must be unexpired and a belong to the attested nodes.
	// NOTE: gRPC will reuse connections from agents and therefore, we can't
	// rely on TLS handshakes to verify certificate validity since the
	// certificate on the connection could have expired after the initial
	// handshake.
	if h.c.Clock.Now().After(cert.NotAfter) {
		return fmt.Errorf("agent %q SVID has expired", agentID)
	}

	resp, err := ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{
		SpiffeId: agentID,
	})
	if err != nil {
		return err
	}

	node := resp.Node
	if node == nil {
		return fmt.Errorf("agent %q is not attested", agentID)
	}
	if node.CertSerialNumber != cert.SerialNumber.String() {
		return fmt.Errorf("agent %q SVID does not match expected serial number", agentID)
	}

	return nil
}

func (h *Handler) validateDownstreamSVID(ctx context.Context, cert *x509.Certificate) (*common.RegistrationEntry, error) {
	peerID, err := getSpiffeIDFromCert(cert)
	if err != nil {
		return nil, err
	}

	// peer SVIDs must be unexpired and have a corresponding downstream entry
	if h.c.Clock.Now().After(cert.NotAfter) {
		return nil, fmt.Errorf("peer %q SVID has expired", peerID)
	}

	return h.getDownstreamEntry(ctx, peerID)
}

func (h *Handler) doAttestChallengeResponse(ctx context.Context,
	nodeStream node.Node_AttestServer,
	attestStream nodeattestor.NodeAttestor_AttestClient,
	request *node.AttestRequest, attestedBefore bool) (*nodeattestor.AttestResponse, error) {
	// challenge/response loop
	for {
		response, err := h.attest(ctx, attestStream, request, attestedBefore)
		if err != nil {
			h.c.Log.Error(err)
			return nil, fmt.Errorf("failed to attest: %v", err)
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
	attestStream nodeattestor.NodeAttestor_AttestClient,
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

	ds := h.c.Catalog.GetDataStore()
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

	if time.Unix(t.Expiry, 0).Before(h.c.Clock.Now()) {
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
		return errors.New("attestation is invalid")
	}
	//check if baseSPIFFEID in attest response matches with SPIFFEID in CSR
	if attestResponse.BaseSPIFFEID != csrBaseSpiffeID {
		return errors.New("attested SPIFFE ID does not match CSR")
	}

	return nil
}

func (h *Handler) updateAttestationEntry(ctx context.Context, cert *x509.Certificate) error {
	ds := h.c.Catalog.GetDataStore()

	spiffeID, err := getSpiffeIDFromCert(cert)
	if err != nil {
		return err
	}

	req := &datastore.UpdateAttestedNodeRequest{
		SpiffeId:         spiffeID,
		CertNotAfter:     cert.NotAfter.Unix(),
		CertSerialNumber: cert.SerialNumber.String(),
	}
	if _, err := ds.UpdateAttestedNode(ctx, req); err != nil {
		return err
	}

	return nil
}

func (h *Handler) createAttestationEntry(ctx context.Context, cert *x509.Certificate, attestationType string) error {
	ds := h.c.Catalog.GetDataStore()
	return createAttestationEntry(ctx, ds, cert, attestationType)
}

func (h *Handler) updateNodeSelectors(ctx context.Context,
	baseSpiffeID string, attestResponse *nodeattestor.AttestResponse, attestationType string) error {

	var selectors []*common.Selector

	// Select node resolver based on request attestation type
	nodeResolver, ok := h.c.Catalog.GetNodeResolverNamed(attestationType)
	if ok {
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
	} else {
		h.c.Log.Debugf("could not find node resolver type %q", attestationType)
	}

	selectors = append(selectors, attestResponse.Selectors...)

	ds := h.c.Catalog.GetDataStore()
	_, err := ds.SetNodeSelectors(ctx, &datastore.SetNodeSelectorsRequest{
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

	regEntries, err := regentryutil.FetchRegistrationEntries(ctx, h.c.Catalog.GetDataStore(), baseSpiffeID)
	if err != nil {
		return nil, err
	}

	bundles, err := h.getBundlesForEntries(ctx, regEntries)
	if err != nil {
		return nil, err
	}

	return &node.AttestResponse{
		SvidUpdate: &node.X509SVIDUpdate{
			Svids:               svids,
			RegistrationEntries: regEntries,
			Bundles:             bundles,
		},
	}, nil
}

func (h *Handler) getDownstreamEntry(ctx context.Context, callerID string) (*common.RegistrationEntry, error) {
	ds := h.c.Catalog.GetDataStore()
	response, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		BySpiffeId: &wrappers.StringValue{
			Value: callerID,
		},
	})

	if err != nil {
		return nil, err
	}

	for _, entry := range response.Entries {
		if (entry.SpiffeId == callerID) && (entry.Downstream) {
			return entry, nil
		}
	}

	return nil, fmt.Errorf("%q is not an authorized downstream workload", callerID)
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

	ds := h.c.Catalog.GetDataStore()
	svids = make(map[string]*node.X509SVID)
	//iterate the CSRs and sign them
	for _, csr := range csrs {
		spiffeID, err := getSpiffeIDFromCSR(csr, idutil.AllowAny())
		if err != nil {
			return nil, err
		}

		baseSpiffeIDPrefix := fmt.Sprintf("%s/spire/agent", h.c.TrustDomain.String())

		sourceAddress := "unknown"
		if peerAddress, ok := getPeerAddress(ctx); ok {
			sourceAddress = peerAddress.String()
		}

		signLog := h.c.Log.WithFields(logrus.Fields{
			"caller_id":      callerID,
			"spiffe_id":      spiffeID,
			"source_address": sourceAddress,
		})

		if spiffeID == callerID && strings.HasPrefix(callerID, baseSpiffeIDPrefix) {
			res, err := ds.FetchAttestedNode(ctx,
				&datastore.FetchAttestedNodeRequest{SpiffeId: spiffeID},
			)
			if err != nil {
				return nil, err
			}
			// attested node discrepancies are not likely since the agent
			// certificate is checked against the attested nodes during the
			// authentication step. however, it is possible that an agent is
			// evicted between authentication and here so these checks should
			// remain.
			if res.Node == nil {
				return nil, errors.New("no record of attested node")
			}
			if res.Node.CertSerialNumber != peerCert.SerialNumber.String() {
				return nil, errors.New("SVID serial number does not match")
			}

			signLog.Debug("Renewing agent SVID")
			svid, svidCert, err := h.buildBaseSVID(ctx, csr)
			if err != nil {
				return nil, err
			}
			svids[spiffeID] = svid

			if err := h.updateAttestationEntry(ctx, svidCert); err != nil {
				return nil, err
			}
		} else {
			signLog.Debug("Signing SVID")
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
		return nil, fmt.Errorf("not entitled to sign CSR for %q", spiffeID)
	}

	svid, err := h.c.ServerCA.SignX509SVID(ctx, csr,
		ca.X509Params{
			TTL:     time.Duration(entry.Ttl) * time.Second,
			DNSList: entry.DnsNames,
		},
	)
	if err != nil {
		return nil, err
	}
	return makeX509SVID(svid), nil
}

func (h *Handler) buildBaseSVID(ctx context.Context, csr []byte) (*node.X509SVID, *x509.Certificate, error) {
	svid, err := h.c.ServerCA.SignX509SVID(ctx, csr, ca.X509Params{})
	if err != nil {
		return nil, nil, err
	}

	return makeX509SVID(svid), svid[0], nil
}

func (h *Handler) buildCASVID(ctx context.Context, csr []byte, params ca.X509Params) (*node.X509SVID, error) {
	svid, err := h.c.ServerCA.SignX509CASVID(ctx, csr, params)
	if err != nil {
		return nil, err
	}

	return makeX509SVID(svid), nil
}

func (h *Handler) getBundlesForEntries(ctx context.Context, regEntries []*common.RegistrationEntry) (map[string]*common.Bundle, error) {
	bundles := make(map[string]*common.Bundle)

	ourBundle, err := h.getBundle(ctx, h.c.TrustDomain.String())
	if err != nil {
		return nil, err
	}
	bundles[ourBundle.TrustDomainId] = ourBundle

	for _, entry := range regEntries {
		for _, trustDomainID := range entry.FederatesWith {
			if bundles[trustDomainID] != nil {
				continue
			}
			bundle, err := h.getBundle(ctx, trustDomainID)
			if err != nil {
				return nil, err
			}
			bundles[trustDomainID] = bundle
		}
	}
	return bundles, nil
}

// getBundle fetches a bundle from the datastore, by trust domain
func (h *Handler) getBundle(ctx context.Context, trustDomainID string) (*common.Bundle, error) {
	ds := h.c.Catalog.GetDataStore()

	resp, err := ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: trustDomainID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch bundle: %v", err)
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

func createAttestationEntry(ctx context.Context, ds datastore.DataStore, cert *x509.Certificate, attestationType string) error {
	spiffeID, err := getSpiffeIDFromCert(cert)
	if err != nil {
		return err
	}
	req := &datastore.CreateAttestedNodeRequest{
		Node: &common.AttestedNode{
			AttestationDataType: attestationType,
			SpiffeId:            spiffeID,
			CertNotAfter:        cert.NotAfter.Unix(),
			CertSerialNumber:    cert.SerialNumber.String(),
		}}
	if _, err := ds.CreateAttestedNode(ctx, req); err != nil {
		return err
	}

	return nil
}

func getSpiffeIDFromCSR(csrBytes []byte, mode idutil.ValidationMode) (string, error) {
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse CSR: %v", err)
	}
	if len(csr.URIs) != 1 {
		return "", errors.New("the CSR must have exactly one URI SAN")
	}

	spiffeID, err := idutil.NormalizeSpiffeIDURL(csr.URIs[0], mode)
	if err != nil {
		return "", err
	}
	return spiffeID.String(), nil
}

func getSpiffeIDFromCert(cert *x509.Certificate) (string, error) {
	if len(cert.URIs) == 0 {
		return "", errors.New("no URI SANs in certificate")
	}
	spiffeID, err := idutil.NormalizeSpiffeIDURL(cert.URIs[0], idutil.AllowAny())
	if err != nil {
		return "", err
	}
	return spiffeID.String(), nil
}

func makeX509SVID(svid []*x509.Certificate) *node.X509SVID {
	var certChain []byte
	for _, cert := range svid {
		certChain = append(certChain, cert.Raw...)
	}
	return &node.X509SVID{
		CertChain: certChain,
		ExpiresAt: svid[0].NotAfter.Unix(),
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

type downstreamEntryKey struct{}

func withDownstreamEntry(ctx context.Context, entry *common.RegistrationEntry) context.Context {
	return context.WithValue(ctx, downstreamEntryKey{}, entry)
}

func getDownstreamEntry(ctx context.Context) (*common.RegistrationEntry, bool) {
	entry, ok := ctx.Value(downstreamEntryKey{}).(*common.RegistrationEntry)
	return entry, ok
}

func getPeerAddress(ctx context.Context) (addr net.Addr, ok bool) {
	p, ok := peer.FromContext(ctx)
	if ok {
		return p.Addr, true
	}
	return nil, false
}
