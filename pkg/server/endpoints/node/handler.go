package node

import (
	"crypto"
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
	telemetry_common "github.com/spiffe/spire/pkg/common/telemetry/common"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
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

	// Allow agentless SPIFFE IDs when doing node attestation
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
	counter := telemetry_server.StartNodeAPIAttestCall(h.c.Metrics)
	defer counter.Done(&err)

	log := h.c.Log

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

	csr, err := h.parseAttestCSR(request.Csr)
	if err != nil {
		log.WithError(err).Error("Failed to parse CSR")
		return status.Errorf(codes.InvalidArgument, "request CSR is invalid: %v", err)
	}

	// Pick the right node attestor
	var attestResponse *nodeattestor.AttestResponse
	if request.AttestationData.Type != "join_token" {
		// New attestor plugins don't provide a SPIFFE ID to the agent so the
		// CSR will not have one. If we have a SPIFFE ID in the CSR then we're
		// working with a legacy plugin and need to provide deprecated
		// "attested before" information to the server side plugin so it can
		// make re-attestation decisions.
		//
		// If the CSR does not provide a SPIFFE ID then we tell the plugin
		// that the agent has already attested to prevent old plugins from
		// re-attesting unsafely.
		//
		// TODO: remove in SPIRE 0.10
		attestedBefore := true
		if csr.SpiffeID != "" {
			attestedBefore, err = h.isAttested(ctx, csr.SpiffeID)
			if err != nil {
				h.c.Log.Error(err)
				return errors.New("failed to determine if agent has already attested")
			}
		}

		nodeAttestor, ok := h.c.Catalog.GetNodeAttestorNamed(request.AttestationData.Type)
		if !ok {
			return fmt.Errorf("could not find node attestor type %q", request.AttestationData.Type)
		}

		attestStream, err := nodeAttestor.Attest(ctx)
		if err != nil {
			return fmt.Errorf("unable to open attest stream: %v", err)
		}

		attestResponse, err = h.doAttestChallengeResponse(ctx, stream, attestStream, request, attestedBefore)
		if err != nil {
			return err
		}
		if err := attestStream.CloseSend(); err != nil {
			return err
		}
		if _, err := attestStream.Recv(); err != io.EOF {
			log.WithError(err).Warn("expected EOF on attestation stream")
		}
	} else {
		attestResponse, err = h.attestToken(ctx, request.AttestationData)
		if err != nil {
			return fmt.Errorf("failed to attest: %v", err)
		}
	}

	agentID := attestResponse.AgentId
	telemetry_common.AddSPIFFEID(counter, agentID)
	log = log.WithField(telemetry.SPIFFEID, agentID)

	if csr.SpiffeID != "" && agentID != csr.SpiffeID {
		log.WithField("csr_spiffe_id", csr.SpiffeID).Error("Attested SPIFFE ID does not match CSR")
		return errors.New("attestor returned unexpected response")
	}

	log.WithField("agent_id", agentID).Debugf("Signing CSR for Agent SVID")
	svid, err := h.c.ServerCA.SignX509SVID(ctx, ca.X509SVIDParams{
		SpiffeID:  agentID,
		PublicKey: csr.PublicKey,
	})
	if err != nil {
		log.WithError(err).Error("Failed to sign CSR")
		return errors.New("failed to sign CSR")
	}

	if err := h.updateNodeSelectors(ctx, agentID, attestResponse, request.AttestationData.Type); err != nil {
		log.WithError(err).Error("Failed to update node selectors")
		return errors.New("failed to update node selectors")
	}

	response, err := h.getAttestResponse(ctx, agentID, svid)
	if err != nil {
		log.WithError(err).Error("Failed to compose response")
		return errors.New("failed to compose response")
	}

	isAttested, err := h.isAttested(ctx, agentID)
	switch {
	case err != nil:
		log.WithError(err).Error("Failed to determine if agent has already attested")
		return errors.New("failed to determine if agent has already attested")
	case isAttested:
		if err := h.updateAttestationEntry(ctx, svid[0]); err != nil {
			log.WithError(err).Error("Failed to update attestation entry")
			return errors.New("failed to update attestation entry")
		}
	default:
		if err := h.createAttestationEntry(ctx, svid[0], request.AttestationData.Type); err != nil {
			log.WithError(err).Error("Failed to create attestation entry")
			return errors.New("failed to create attestation entry")
		}
	}

	p, ok := peer.FromContext(ctx)
	if ok {
		log.WithFields(logrus.Fields{
			telemetry.Attestor: request.AttestationData.Type,
			telemetry.Address:  p.Addr,
		}).Info("Node attestation request completed")
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
	counter := telemetry_server.StartNodeAPIFetchX509SVIDCall(h.c.Metrics)
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
		csrsLenDeprecated := len(request.DEPRECATEDCsrs)
		csrsLen := len(request.Csrs)

		err = h.limiter.Limit(ctx, CSRMsg, max(csrsLen, csrsLenDeprecated))
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

		// Only one of 'CSRs', 'DEPRECATEDCSRs' must be populated
		if csrsLen != 0 && csrsLenDeprecated != 0 {
			return errors.New("cannot use 'Csrs' and 'DeprecatedCsrs' on the same 'FetchX509Request'")
		}

		// Select how to sign the SVIDs based on the agent version
		var svids map[string]*node.X509SVID
		var spiffeIDs []string

		if csrsLen != 0 {
			// Current agent, use regular signCSRs (it returns svids keyed by entryID)
			svids, spiffeIDs, err = h.signCSRs(ctx, peerCert, request.Csrs, regEntries)
			if err != nil {
				h.c.Log.Error(err)
				return errors.New("failed to sign CSRs")
			}

			// Add entryID and spiffeID to counter
			for entryID := range svids {
				telemetry_common.AddRegistrationID(counter, entryID)
			}
			for _, spiffeID := range spiffeIDs {
				telemetry_common.AddSPIFFEID(counter, spiffeID)
			}

		} else if csrsLenDeprecated != 0 {
			// Legacy agent, use legacy SignCSRs (it returns svids keyed by spiffeID)
			svids, err = h.signCSRsLegacy(ctx, peerCert, request.DEPRECATEDCsrs, regEntries)
			if err != nil {
				h.c.Log.Error(err)
				return errors.New("failed to sign CSRs")
			}

			// Add spiffeID to counter (entryID is not available)
			for spiffeID := range svids {
				telemetry_common.AddSPIFFEID(counter, spiffeID)
			}
		} else {
			// If both are zero, there is not CSR to sign -> assign an empty map
			svids = make(map[string]*node.X509SVID)
		}

		bundles, err := h.getBundlesForEntries(ctx, regEntries)
		if err != nil {
			h.c.Log.Error(err)
			return err
		}

		err = server.Send(&node.FetchX509SVIDResponse{
			SvidUpdate: &node.X509SVIDUpdate{
				Svids:               svids,
				RegistrationEntries: regEntries,
				Bundles:             bundles,
			},
		})
		if err != nil {
			h.c.Log.WithError(err).Error("Error sending FetchX509SVIDResponse")
		}
	}
}

func (h *Handler) FetchX509CASVID(ctx context.Context, req *node.FetchX509CASVIDRequest) (_ *node.FetchX509CASVIDResponse, err error) {
	counter := telemetry.StartCall(h.c.Metrics, "node_api", "x509_ca_svid", "fetch")
	defer counter.Done(&err)

	peerCert, ok := getPeerCertificate(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "downstream SVID is required for this request")
	}

	entry, ok := getDownstreamEntry(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "downstream entry is required for this request")
	}

	err = h.limiter.Limit(ctx, CSRMsg, 1)
	if err != nil {
		return nil, status.Error(codes.ResourceExhausted, err.Error())
	}

	downstreamID, err := getSpiffeIDFromCert(peerCert)
	if err != nil {
		h.c.Log.Error(err)
		return nil, err
	}

	sourceAddress := "unknown"
	if peerAddress, ok := getPeerAddress(ctx); ok {
		sourceAddress = peerAddress.String()
	}

	signLog := h.c.Log.WithFields(logrus.Fields{
		telemetry.CallerID: downstreamID,
		telemetry.Address:  sourceAddress,
	})

	csr, err := h.parseX509CACSR(req.Csr)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	signLog.Debug("Signing downstream CA SVID")
	svid, err := h.buildCASVID(ctx, ca.X509CASVIDParams{
		SpiffeID:  csr.SpiffeID,
		PublicKey: csr.PublicKey,
		TTL:       time.Duration(entry.Ttl) * time.Second,
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
	counter := telemetry_server.StartNodeAPIFetchJWTSVIDCall(h.c.Metrics)
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

	telemetry_common.AddSPIFFEID(counter, req.Jsr.SpiffeId)

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

	telemetry_common.AddAudience(counter, req.Jsr.Audience...)

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
			return nil, status.Error(codes.Unauthenticated, "agent SVID is required for this request")
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
			return nil, status.Error(codes.Unauthenticated, "downstream SVID is required for this request")
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

	attestRequest := &nodeattestor.AttestRequest{
		AttestationData:          nodeRequest.AttestationData,
		Response:                 nodeRequest.Response,
		DEPRECATEDAttestedBefore: attestedBefore,
	}
	if err := attestStream.Send(attestRequest); err != nil {
		return nil, err
	}

	return attestStream.Recv()
}

func (h *Handler) attestToken(ctx context.Context, attestationData *common.AttestationData) (*nodeattestor.AttestResponse, error) {
	tokenValue := string(attestationData.Data)

	agentID := (&url.URL{
		Scheme: "spiffe",
		Host:   h.c.TrustDomain.Host,
		Path:   path.Join("spire", "agent", "join_token", tokenValue),
	}).String()

	attestedBefore, err := h.isAttested(ctx, agentID)
	switch {
	case err != nil:
		h.c.Log.Error(err)
		return nil, errors.New("failed to determine if agent has already attested")
	case attestedBefore:
		return nil, errors.New("join token has already been used")
	}

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
	return &nodeattestor.AttestResponse{
		AgentId: agentID,
	}, nil
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
		h.c.Log.WithField(telemetry.Attestor, attestationType).Debug("could not find node resolver")
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

// signCSRsLegacy receives CSRs as a slice of []bytes in contrast with 'SignCSRs'.
// This function is used to handle legacy agents request that use
// the 'DEPRECATED_csrs' field of the 'FetchX509SVIDRequest' message.
// TODO: remove this function when 'DEPRECATED_csrs' gets removed
func (h *Handler) signCSRsLegacy(ctx context.Context,
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
	for _, csrBytes := range csrs {
		csr, err := parseCSR(csrBytes, idutil.AllowAny())
		if err != nil {
			return nil, err
		}

		baseSpiffeIDPrefix := fmt.Sprintf("%s/spire/agent", h.c.TrustDomain.String())

		sourceAddress := "unknown"
		if peerAddress, ok := getPeerAddress(ctx); ok {
			sourceAddress = peerAddress.String()
		}

		signLog := h.c.Log.WithFields(logrus.Fields{
			telemetry.CallerID: callerID,
			telemetry.SPIFFEID: csr.SpiffeID,
			telemetry.Address:  sourceAddress,
		})

		if csr.SpiffeID == callerID && strings.HasPrefix(callerID, baseSpiffeIDPrefix) {
			res, err := ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{
				SpiffeId: csr.SpiffeID,
			})
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
			svids[csr.SpiffeID] = svid

			if err := h.updateAttestationEntry(ctx, svidCert); err != nil {
				return nil, err
			}
		} else {
			signLog.Debug("Signing SVID")
			svid, err := h.buildSVID(ctx, csr.SpiffeID, csr, regEntriesMap)
			if err != nil {
				return nil, err
			}
			svids[csr.SpiffeID] = svid
		}
	}

	return svids, nil
}

func (h *Handler) signCSRs(ctx context.Context,
	peerCert *x509.Certificate, csrs map[string][]byte, regEntries []*common.RegistrationEntry) (
	svids map[string]*node.X509SVID, spiffeIDs []string, err error) {

	callerID, err := getSpiffeIDFromCert(peerCert)
	if err != nil {
		return nil, nil, err
	}

	//convert registration entries into a map for easy lookup
	regEntriesMap := make(map[string]*common.RegistrationEntry)
	for _, entry := range regEntries {
		regEntriesMap[entry.EntryId] = entry
	}

	ds := h.c.Catalog.GetDataStore()
	svids = make(map[string]*node.X509SVID)
	//iterate the CSRs and sign them
	for entryID, csrBytes := range csrs {
		csr, err := parseCSR(csrBytes, idutil.AllowAny())
		if err != nil {
			return nil, nil, err
		}

		baseSpiffeIDPrefix := fmt.Sprintf("%s/spire/agent", h.c.TrustDomain.String())

		sourceAddress := "unknown"
		if peerAddress, ok := getPeerAddress(ctx); ok {
			sourceAddress = peerAddress.String()
		}

		signLog := h.c.Log.WithFields(logrus.Fields{
			telemetry.CallerID: callerID,
			telemetry.SPIFFEID: csr.SpiffeID,
			telemetry.Address:  sourceAddress,
		})

		if csr.SpiffeID == callerID && strings.HasPrefix(callerID, baseSpiffeIDPrefix) {
			res, err := ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{
				SpiffeId: csr.SpiffeID,
			})
			if err != nil {
				return nil, nil, err
			}
			// attested node discrepancies are not likely since the agent
			// certificate is checked against the attested nodes during the
			// authentication step. however, it is possible that an agent is
			// evicted between authentication and here so these checks should
			// remain.
			if res.Node == nil {
				return nil, nil, errors.New("no record of attested node")
			}
			if res.Node.CertSerialNumber != peerCert.SerialNumber.String() {
				return nil, nil, errors.New("SVID serial number does not match")
			}

			signLog.Debug("Renewing agent SVID")
			svid, svidCert, err := h.buildBaseSVID(ctx, csr)
			if err != nil {
				return nil, nil, err
			}
			svids[entryID] = svid

			if err := h.updateAttestationEntry(ctx, svidCert); err != nil {
				return nil, nil, err
			}
		} else {
			signLog.Debug("Signing SVID")
			svid, err := h.buildSVID(ctx, entryID, csr, regEntriesMap)
			if err != nil {
				return nil, nil, err
			}
			svids[entryID] = svid
		}

		spiffeIDs = append(spiffeIDs, csr.SpiffeID)
	}

	return svids, spiffeIDs, nil
}

func (h *Handler) buildSVID(ctx context.Context, id string, csr *CSR, regEntries map[string]*common.RegistrationEntry) (*node.X509SVID, error) {
	entry, ok := regEntries[id]
	if !ok {
		var idType string
		if strings.HasPrefix(id, "spiffe://") {
			idType = "SPIFFE ID"
		} else {
			idType = "registration entry ID"
		}
		return nil, fmt.Errorf("not entitled to sign CSR for %s %q", idType, id)
	}

	svid, err := h.c.ServerCA.SignX509SVID(ctx, ca.X509SVIDParams{
		SpiffeID:  csr.SpiffeID,
		PublicKey: csr.PublicKey,
		TTL:       time.Duration(entry.Ttl) * time.Second,
		DNSList:   entry.DnsNames,
	})
	if err != nil {
		return nil, err
	}
	return makeX509SVID(svid), nil
}

func (h *Handler) buildBaseSVID(ctx context.Context, csr *CSR) (*node.X509SVID, *x509.Certificate, error) {
	svid, err := h.c.ServerCA.SignX509SVID(ctx, ca.X509SVIDParams{
		SpiffeID:  csr.SpiffeID,
		PublicKey: csr.PublicKey,
	})
	if err != nil {
		return nil, nil, err
	}

	return makeX509SVID(svid), svid[0], nil
}

func (h *Handler) buildCASVID(ctx context.Context, params ca.X509CASVIDParams) (*node.X509SVID, error) {
	svid, err := h.c.ServerCA.SignX509CASVID(ctx, params)
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

type CSR struct {
	SpiffeID  string
	PublicKey crypto.PublicKey
}

func (h *Handler) parseAttestCSR(csrBytes []byte) (*CSR, error) {
	if h.c.AllowAgentlessNodeAttestors {
		return parseCSR(csrBytes, idutil.AllowAnyInTrustDomain(h.c.TrustDomain.Host))
	}
	return parseCSR(csrBytes, idutil.AllowTrustDomainAgent(h.c.TrustDomain.Host))
}

func (h *Handler) parseX509CACSR(csrBytes []byte) (*CSR, error) {
	csr, err := parseCSR(csrBytes, idutil.AllowTrustDomain(h.c.TrustDomain.Host))
	if err != nil {
		return nil, err
	}
	if csr.SpiffeID == "" {
		return nil, errors.New("X509 CA CSR is missing the SPIFFE ID")
	}
	return csr, nil
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

func parseCSR(csrBytes []byte, mode idutil.ValidationMode) (*CSR, error) {
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, fmt.Errorf("request CSR is invalid: failed to parse CSR: %v", err)
	}

	var spiffeID string
	switch len(csr.URIs) {
	case 0:
	case 1:
		spiffeID, err = idutil.NormalizeSpiffeID(csr.URIs[0].String(), mode)
		if err != nil {
			return nil, fmt.Errorf("request CSR is invalid: invalid SPIFFE ID: %v", err)
		}
	default:
		return nil, errors.New("request CSR is invalid: cannot have more than one URI SAN")
	}

	return &CSR{
		SpiffeID:  spiffeID,
		PublicKey: csr.PublicKey,
	}, nil
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

// max returns the larger of x or y.
func max(x, y int) int {
	if x < y {
		return y
	}
	return x
}
