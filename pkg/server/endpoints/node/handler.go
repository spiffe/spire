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
	"github.com/spiffe/spire/pkg/common/errorutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/nodeutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_common "github.com/spiffe/spire/pkg/common/telemetry/common"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/cache/dscache"
	"github.com/spiffe/spire/pkg/server/cache/entrycache"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/server/plugin/noderesolver"
	"github.com/spiffe/spire/pkg/server/util/regentryutil"
	"github.com/spiffe/spire/proto/spire/api/node"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/types"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Number of agentIDs that can be cached
const fetchSVIDCacheSize = 500_000

type HandlerConfig struct {
	Log         logrus.FieldLogger
	Metrics     telemetry.Metrics
	Catalog     catalog.Catalog
	ServerCA    ca.ServerCA
	TrustDomain url.URL
	Clock       clock.Clock
	Manager     *ca.Manager

	// RateLimitAttestation, if true, rate limits attestation.
	RateLimitAttestation bool

	// Allow agentless SPIFFE IDs when doing node attestation
	AllowAgentlessNodeAttestors bool
}

type Handler struct {
	c       HandlerConfig
	limiter Limiter

	fetchRegistrationEntriesCache *entrycache.FetchRegistrationEntriesCache
}

func NewHandler(config HandlerConfig) (*Handler, error) {
	if config.Clock == nil {
		config.Clock = clock.New()
	}
	fetchX509SVIDCache, err := entrycache.NewFetchX509SVIDCache(fetchSVIDCacheSize)
	if err != nil {
		return nil, fmt.Errorf("could not create cache: %v", err)
	}

	return &Handler{
		c:                             config,
		limiter:                       NewLimiter(config.Log, config.RateLimitAttestation),
		fetchRegistrationEntriesCache: fetchX509SVIDCache,
	}, nil
}

//Attest attests the node and gets the base node SVID.
func (h *Handler) Attest(stream node.Node_AttestServer) (err error) {
	counter := telemetry_server.StartNodeAPIAttestCall(h.c.Metrics)
	attestorName := ""
	defer func() {
		telemetry_common.AddAttestorType(counter, attestorName)
		counter.Done(&err)
	}()

	log := h.c.Log.WithField(telemetry.Method, telemetry.NodeAPI)

	// make sure node attestor stream will be cancelled if things go awry
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	// pull off the initial request
	request, err := stream.Recv()
	if err != nil {
		log.WithError(err).Error("Failed to receive request from stream")
		return status.Error(codes.InvalidArgument, err.Error())
	}

	err = h.limiter.Limit(ctx, AttestMsg, 1)
	if err != nil {
		log.WithError(err).Error("Rejecting request due to node attestation rate limiting")
		return status.Error(codes.ResourceExhausted, err.Error())
	}

	if request.AttestationData == nil {
		log.Error("Request missing attestation data")
		return status.Error(codes.InvalidArgument, "request missing attestation data")
	}
	if request.AttestationData.Type == "" {
		log.Error("Request missing attestation data type")
		return status.Error(codes.InvalidArgument, "request missing attestation data type")
	}
	attestorName = request.AttestationData.Type
	log = log.WithField(telemetry.Attestor, request.AttestationData.Type)

	if len(request.Csr) == 0 {
		log.Error("Request missing CSR")
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
		nodeAttestorType := request.AttestationData.Type
		nodeAttestor, ok := h.c.Catalog.GetNodeAttestorNamed(nodeAttestorType)
		if !ok {
			log.WithField(telemetry.NodeAttestorType, nodeAttestorType).Error("Could not find node attestor type")
			return status.Error(codes.Unimplemented, fmt.Sprintf("could not find node attestor type %q", nodeAttestorType))
		}

		attestStream, err := nodeAttestor.Attest(ctx)
		if err != nil {
			log.WithError(err).Error("Unable to open attest stream")
			return errorutil.WrapError(err, "unable to open attest stream")
		}

		attestResponse, err = h.doAttestChallengeResponse(stream, attestStream, request)
		if err != nil {
			log.WithError(err).Error("Failed to do node attest challenge response")
			return err
		}
		if err := attestStream.CloseSend(); err != nil {
			log.WithError(err).Error("Failed to close send stream")
			return status.Error(codes.Internal, err.Error())
		}
		if _, err := attestStream.Recv(); err != io.EOF {
			log.WithError(err).Warn("Expected EOF on attestation stream")
		}
	} else {
		attestResponse, err = h.attestToken(ctx, request.AttestationData)
		if err != nil {
			log.WithError(err).Error("Failed to attest")
			return errorutil.WrapError(err, "failed to attest")
		}
	}

	agentID := attestResponse.AgentId
	log = log.WithField(telemetry.SPIFFEID, agentID)

	isBanned, err := h.isBanned(ctx, agentID)
	switch {
	case err != nil:
		log.WithError(err).Error("Failed to determine if agent is banned")
		return status.Errorf(codes.Internal, "failed to determine if agent is banned: %v", err)
	case isBanned:
		return status.Error(codes.PermissionDenied, "agent is banned")
	}

	if csr.SpiffeID != "" && agentID != csr.SpiffeID {
		log.WithField(telemetry.CsrSpiffeID, csr.SpiffeID).Error("Attested SPIFFE ID does not match CSR")
		return status.Error(codes.NotFound, "attestor returned unexpected response")
	}

	log.WithField(telemetry.AgentID, agentID).Debugf("Signing CSR for Agent SVID")
	svid, err := h.c.ServerCA.SignX509SVID(ctx, ca.X509SVIDParams{
		SpiffeID:  agentID,
		PublicKey: csr.PublicKey,
	})
	if err != nil {
		log.WithError(err).Error("Failed to sign CSR")
		return status.Error(codes.Internal, "failed to sign CSR")
	}

	if err := h.updateNodeSelectors(ctx, agentID, attestResponse, request.AttestationData.Type); err != nil {
		log.WithError(err).Error("Failed to update node selectors")
		return status.Error(codes.Internal, "failed to update node selectors")
	}

	response, err := h.getAttestResponse(ctx, agentID, svid)
	if err != nil {
		log.WithError(err).Error("Failed to compose response")
		return status.Error(codes.Internal, "failed to compose response")
	}

	isAttested, err := h.isAttested(ctx, agentID)
	switch {
	case err != nil:
		log.WithError(err).Error("Failed to determine if agent has already attested")
		return status.Error(codes.Internal, "failed to determine if agent has already attested")
	case isAttested:
		req := &datastore.UpdateAttestedNodeRequest{
			SpiffeId:         agentID,
			CertNotAfter:     svid[0].NotAfter.Unix(),
			CertSerialNumber: svid[0].SerialNumber.String(),
		}

		if err := h.updateAttestedNode(ctx, req); err != nil {
			log.WithError(err).Error("Failed to update attestation entry")
			return status.Error(codes.Internal, "failed to update attestation entry")
		}
	default:
		if err := h.createAttestationEntry(ctx, svid[0], request.AttestationData.Type); err != nil {
			log.WithError(err).Error("Failed to create attestation entry")
			return status.Error(codes.Internal, "failed to create attestation entry")
		}
	}

	p, ok := peer.FromContext(ctx)
	if ok {
		log.WithField(telemetry.Address, p.Addr.String()).Info("Node attestation request completed")
	}

	if err := stream.Send(response); err != nil {
		log.WithError(err).Error("Failed to send response over stream")
		return status.Error(codes.Internal, err.Error())
	}

	return nil
}

//FetchX509SVID gets Workload, Agent certs and CA trust bundles.
//Also used for rotation Base Node SVID or the Registered Node SVID used for this call.
//List can be empty to allow Node Agent cache refresh).
func (h *Handler) FetchX509SVID(server node.Node_FetchX509SVIDServer) (err error) {
	counter := telemetry_server.StartNodeAPIFetchX509SVIDCall(h.c.Metrics)
	defer counter.Done(&err)
	log := h.c.Log.WithField(telemetry.Method, telemetry.FetchX509SVID)

	peerCert, ok := getPeerCertificate(server.Context())
	if !ok {
		log.Error("Request missing client SVID")
		return status.Error(codes.InvalidArgument, "client SVID is required for this request")
	}

	for {
		request, err := server.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			log.WithError(err).Error("Error receiving request from stream")
			return status.Error(codes.Internal, err.Error())
		}

		ctx := server.Context()

		err = h.limiter.Limit(ctx, CSRMsg, len(request.Csrs))
		if err != nil {
			log.WithError(err).Error("Rejecting request due to certificate signing rate limiting")
			return status.Error(codes.ResourceExhausted, err.Error())
		}

		agentID, err := getSpiffeIDFromCert(peerCert)
		if err != nil {
			log.WithError(err).Error("Error getting SPIFFE ID from peer certificate")
			return status.Error(codes.InvalidArgument, err.Error())
		}

		regEntries, err := regentryutil.FetchRegistrationEntriesWithCache(ctx, h.c.Catalog.GetDataStore(), h.fetchRegistrationEntriesCache, agentID)
		if err != nil {
			log.WithError(err).Error("Failed to fetch agent registration entries")
			return status.Error(codes.Internal, "failed to fetch agent registration entries")
		}

		bundles, err := h.getBundlesForEntries(ctx, regEntries)
		if err != nil {
			log.WithError(err).Error("Failed to get bundles for registration entries")
			return status.Error(codes.Internal, err.Error())
		}

		svids, err := h.signCSRs(ctx, peerCert, request.Csrs, regEntries)
		if err != nil {
			log.WithError(err).Error("Failed to sign CSRs")
			return status.Error(codes.Internal, "failed to sign CSRs")
		}

		err = server.Send(&node.FetchX509SVIDResponse{
			SvidUpdate: &node.X509SVIDUpdate{
				Svids:               svids,
				RegistrationEntries: regEntries,
				Bundles:             bundles,
			},
		})
		if err != nil {
			log.WithError(err).Error("Error sending FetchX509SVIDResponse")
			return status.Error(codes.Internal, err.Error())
		}
	}
}

func (h *Handler) FetchX509CASVID(ctx context.Context, req *node.FetchX509CASVIDRequest) (_ *node.FetchX509CASVIDResponse, err error) {
	counter := telemetry_server.StartNodeAPIFetchX509CASVIDCall(h.c.Metrics)
	defer counter.Done(&err)
	log := h.c.Log.WithField(telemetry.Method, telemetry.FetchX509CASVID)

	peerCert, ok := getPeerCertificate(ctx)
	if !ok {
		log.Error("Downstream SVID is required for this request")
		return nil, status.Error(codes.InvalidArgument, "downstream SVID is required for this request")
	}

	entry, ok := getDownstreamEntry(ctx)
	if !ok {
		log.Error("Downstream entry is required for this request")
		return nil, status.Error(codes.InvalidArgument, "downstream entry is required for this request")
	}

	err = h.limiter.Limit(ctx, CSRMsg, 1)
	if err != nil {
		log.WithError(err).Error("Rejecting request due to certificate signing rate limiting")
		return nil, status.Error(codes.ResourceExhausted, err.Error())
	}

	downstreamID, err := getSpiffeIDFromCert(peerCert)
	if err != nil {
		log.WithError(err).Error("Failed to get SPIFFE ID from certificate")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	sourceAddress := "unknown"
	if peerAddress, ok := getPeerAddress(ctx); ok {
		sourceAddress = peerAddress.String()
	}

	signLog := log.WithFields(logrus.Fields{
		telemetry.CallerID: downstreamID,
		telemetry.Address:  sourceAddress,
	})

	csr, err := h.parseX509CACSR(req.Csr)
	if err != nil {
		log.WithError(err).Error("Failed to parse X.509 CA certificate signing request")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	signLog.Debug("Signing downstream CA SVID")
	svid, err := h.buildCASVID(ctx, ca.X509CASVIDParams{
		SpiffeID:  csr.SpiffeID,
		PublicKey: csr.PublicKey,
		TTL:       time.Duration(entry.Ttl) * time.Second,
	})
	if err != nil {
		log.WithError(err).Error("Failed to sign downstream CA SVID")
		return nil, status.Error(codes.Internal, err.Error())
	}

	bundle, err := h.getBundle(ctx, h.c.TrustDomain.String())
	if err != nil {
		log.WithError(err).Error("Failed to fetch bundle")
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &node.FetchX509CASVIDResponse{
		Svid:   svid,
		Bundle: bundle,
	}, nil
}

func (h *Handler) FetchJWTSVID(ctx context.Context, req *node.FetchJWTSVIDRequest) (resp *node.FetchJWTSVIDResponse, err error) {
	counter := telemetry_server.StartNodeAPIFetchJWTSVIDCall(h.c.Metrics)
	defer counter.Done(&err)
	log := h.c.Log.WithField(telemetry.Method, telemetry.FetchJWTSVID)
	if err := h.limiter.Limit(ctx, JSRMsg, 1); err != nil {
		log.WithError(err).Error("Rejecting request due to JWT signing request rate limiting")
		return nil, status.Error(codes.ResourceExhausted, err.Error())
	}

	peerCert, ok := getPeerCertificate(ctx)
	if !ok {
		log.Error("Request missing client SVID")
		return nil, status.Error(codes.InvalidArgument, "client SVID is required for this request")
	}

	// validate request parameters
	switch {
	case req.Jsr == nil:
		log.Error("Request missing JSR")
		return nil, status.Error(codes.InvalidArgument, "request missing JSR")
	case req.Jsr.SpiffeId == "":
		log.Error("Request missing SPIFFE ID")
		return nil, status.Error(codes.InvalidArgument, "request missing SPIFFE ID")
	case len(req.Jsr.Audience) == 0:
		log.Error("Request missing audience")
		return nil, status.Error(codes.InvalidArgument, "request missing audience")
	}

	agentID, err := getSpiffeIDFromCert(peerCert)
	log = log.WithFields(logrus.Fields{
		telemetry.AgentID:  agentID,
		telemetry.SPIFFEID: req.Jsr.SpiffeId,
	})

	if err != nil {
		log.WithError(err).Error("Failed to get SPIFFE ID from certificate")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	ds := h.c.Catalog.GetDataStore()
	regEntries, err := regentryutil.FetchRegistrationEntries(ctx, ds, agentID)
	if err != nil {
		log.WithError(err).Error("Failed to fetch registration entries")
		return nil, status.Error(codes.Internal, err.Error())
	}

	found := false
	for _, candidateEntry := range regEntries {
		if candidateEntry.SpiffeId == req.Jsr.SpiffeId {
			found = true
			break
		}
	}

	if !found {
		log.Error("Caller is not authorized")
		return nil, status.Error(codes.PermissionDenied, "caller is not authorized")
	}

	token, err := h.c.ServerCA.SignJWTSVID(ctx, ca.JWTSVIDParams{
		SpiffeID: req.Jsr.SpiffeId,
		TTL:      time.Duration(req.Jsr.Ttl) * time.Second,
		Audience: req.Jsr.Audience,
	})
	if err != nil {
		log.WithError(err).Error("Failed to sign JWT-SVID")
		return nil, status.Errorf(codes.Internal, "failed to sign JWT-SVID: %v", err)
	}

	issuedAt, expiresAt, err := jwtsvid.GetTokenExpiry(token)
	if err != nil {
		log.WithError(err).Error("Failed to get JWT-SVID expiry")
		return nil, status.Errorf(codes.Internal, "failed to get JWT-SVID expiry: %v", err)
	}

	return &node.FetchJWTSVIDResponse{
		Svid: &node.JWTSVID{
			Token:     token,
			IssuedAt:  issuedAt.Unix(),
			ExpiresAt: expiresAt.Unix(),
		},
	}, nil
}

func (h *Handler) PushJWTKeyUpstream(ctx context.Context, req *node.PushJWTKeyUpstreamRequest) (resp *node.PushJWTKeyUpstreamResponse, err error) {
	counter := telemetry_server.StartNodeAPIPushJWTKeyUpstreamCall(h.c.Metrics)
	defer counter.Done(&err)
	log := h.c.Log.WithField(telemetry.Method, telemetry.PushJWTKeyUpstream)

	_, ok := getPeerCertificate(ctx)
	if !ok {
		log.Error("Downstream SVID is required for this request")
		return nil, status.Error(codes.InvalidArgument, "downstream SVID is required for this request")
	}

	_, ok = getDownstreamEntry(ctx)
	if !ok {
		log.Error("Downstream entry is required for this request")
		return nil, status.Error(codes.InvalidArgument, "downstream entry is required for this request")
	}

	err = h.limiter.Limit(ctx, PushJWTKey, 1)
	if err != nil {
		log.WithError(err).Error("Rejecting request due to JWK push rate limiting")
		return nil, status.Error(codes.ResourceExhausted, err.Error())
	}

	jwtSigningKeys, err := h.c.Manager.PublishJWTKey(ctx, req.JwtKey)
	if err != nil {
		log.WithError(err).Error("Could not publish new JWT key")
		return nil, status.Errorf(codes.Internal, "error publishing new JWT key: %v", err)
	}

	return &node.PushJWTKeyUpstreamResponse{
		JwtSigningKeys: jwtSigningKeys,
	}, nil
}

func (h *Handler) FetchBundle(ctx context.Context, req *node.FetchBundleRequest) (_ *node.FetchBundleResponse, err error) {
	counter := telemetry_server.StartNodeAPIFetchBundleCall(h.c.Metrics)
	defer counter.Done(&err)
	log := h.c.Log.WithField(telemetry.Method, telemetry.FetchBundle)

	_, ok := getPeerCertificate(ctx)
	if !ok {
		log.Error("Client certificate required for this request")
		return nil, status.Error(codes.InvalidArgument, "client certificate required for this request")
	}

	bundle, err := h.getBundle(ctx, h.c.TrustDomain.String())
	if err != nil {
		log.WithError(err).Error("Failed to fetch bundle")
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &node.FetchBundleResponse{
		Bundle: bundle,
	}, nil
}

func (h *Handler) AuthorizeCall(ctx context.Context, fullMethod string) (_ context.Context, err error) {
	counter := telemetry_server.StartNodeAPIAuthorizeCall(h.c.Metrics, fullMethod)
	defer counter.Done(&err)
	log := h.c.Log.WithField(telemetry.Method, fullMethod)

	switch fullMethod {
	// no authn/authz is required for attestation
	case "/spire.api.node.Node/Attest":

	// peer certificate required for SVID fetching
	case "/spire.api.node.Node/FetchX509SVID",
		"/spire.api.node.Node/FetchJWTSVID":
		agentCert, err := h.getAgentCertificateFromRequestContext(ctx, log)
		if err != nil {
			return nil, err
		}
		ctx = withPeerCertificate(ctx, agentCert)
	case "/spire.api.node.Node/FetchX509CASVID",
		"/spire.api.node.Node/PushJWTKeyUpstream":
		peerCert, err := getPeerCertificateFromRequestContext(ctx)
		if err != nil {
			log.WithError(err).Error("Downstream SVID is required for this request")
			return nil, status.Error(codes.Unauthenticated, "downstream SVID is required for this request")
		}
		entry, err := h.validateDownstreamSVID(ctx, peerCert)
		if err != nil {
			log.WithError(err).Error("Peer is not a valid downstream SPIRE server")
			return nil, status.Error(codes.PermissionDenied, "peer is not a valid downstream SPIRE server")
		}

		ctx = withPeerCertificate(ctx, peerCert)
		ctx = withDownstreamEntry(ctx, entry)
	case "/spire.api.node.Node/FetchBundle":
		peerCert, err := getPeerCertificateFromRequestContext(ctx)
		if err != nil {
			log.WithError(err).Error("Client certificate required for this request")
			return nil, status.Error(codes.Unauthenticated, "client certificate required for this request")
		}

		ctx = withPeerCertificate(ctx, peerCert)
	// method not handled
	default:
		err := status.Errorf(codes.PermissionDenied, "authorization not implemented for method %q", fullMethod)
		log.Error("Authorization not implemented for method")
		return nil, err
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

	n := fetchResponse.Node
	if n != nil && n.SpiffeId == baseSpiffeID {
		return true, nil
	}

	return false, nil
}

func (h *Handler) getAgentCertificateFromRequestContext(ctx context.Context, log logrus.FieldLogger) (*x509.Certificate, error) {
	agentCert, err := getPeerCertificateFromRequestContext(ctx)
	if err != nil {
		log.WithError(err).Error("Agent SVID is required for this request")
		return nil, status.Error(codes.Unauthenticated, "agent SVID is required for this request")
	}

	log = log.WithFields(logrus.Fields{
		telemetry.AgentID: tryGetSpiffeIDFromCert(agentCert),
	})

	if err := h.validateAgentSVID(ctx, agentCert); err != nil {
		log.WithError(err).Error("Agent permission denied")
		return nil, err
	}
	return agentCert, nil
}

func (h *Handler) validateAgentSVID(ctx context.Context, cert *x509.Certificate) error {
	ds := h.c.Catalog.GetDataStore()

	permissionDenied := func(reason types.PermissionDeniedDetails_Reason, format string, args ...interface{}) error {
		st := status.Newf(codes.PermissionDenied, format, args...)
		if detailed, err := st.WithDetails(&types.PermissionDeniedDetails{
			Reason: reason,
		}); err == nil {
			st = detailed
		}
		return st.Err()
	}

	agentID, err := getSpiffeIDFromCert(cert)
	if err != nil {
		return permissionDenied(types.PermissionDeniedDetails_UNKNOWN, "unable to get spiffe ID: %v", err)
	}

	// agent SVIDs must be unexpired and a belong to the attested nodes.
	// NOTE: gRPC will reuse connections from agents and therefore, we can't
	// rely on TLS handshakes to verify certificate validity since the
	// certificate on the connection could have expired after the initial
	// handshake.
	if h.c.Clock.Now().After(cert.NotAfter) {
		return permissionDenied(types.PermissionDeniedDetails_AGENT_EXPIRED, "agent %q SVID has expired", agentID)
	}

	resp, err := ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{
		SpiffeId: agentID,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to fetch agent information: %v", err)
	}

	n := resp.Node
	if n == nil {
		return permissionDenied(types.PermissionDeniedDetails_AGENT_NOT_ATTESTED, "agent %q is not attested", agentID)
	}

	if nodeutil.IsAgentBanned(n) {
		return permissionDenied(types.PermissionDeniedDetails_AGENT_BANNED, "agent %q is banned", agentID)
	}

	if n.CertSerialNumber != "" && n.CertSerialNumber == cert.SerialNumber.String() {
		return nil
	}

	if n.NewCertSerialNumber != "" && n.NewCertSerialNumber == cert.SerialNumber.String() {
		fieldLog := h.c.Log.WithFields(logrus.Fields{"agent": agentID, "new_serial": n.NewCertSerialNumber})
		fieldLog.Debug("Activating agent SVID")
		err := h.updateAttestedNode(ctx, &datastore.UpdateAttestedNodeRequest{
			SpiffeId:         n.SpiffeId,
			CertSerialNumber: n.NewCertSerialNumber,
			CertNotAfter:     n.NewCertNotAfter,
		})

		if err != nil {
			fieldLog.Warningf("Failed to activate agent SVID: %v", err)
			return status.Errorf(codes.Internal, "failed to activate agent %q SVID: %v", agentID, err)
		}
		return nil
	}

	return permissionDenied(types.PermissionDeniedDetails_AGENT_NOT_ACTIVE, "agent %q SVID does not match expected serial number", agentID)
}

func (h *Handler) validateDownstreamSVID(ctx context.Context, cert *x509.Certificate) (*common.RegistrationEntry, error) {
	peerID, err := getSpiffeIDFromCert(cert)
	if err != nil {
		return nil, err
	}

	// peer SVIDs must be unexpired and have a corresponding downstream entry
	if h.c.Clock.Now().After(cert.NotAfter) {
		h.c.Log.WithField(telemetry.PeerID, peerID).Error("Peer SVID has expired")
		return nil, errors.New("peer SVID has expired")
	}

	return h.getDownstreamEntry(ctx, peerID)
}

func (h *Handler) doAttestChallengeResponse(nodeStream node.Node_AttestServer, attestStream nodeattestor.NodeAttestor_AttestClient, request *node.AttestRequest) (*nodeattestor.AttestResponse, error) {
	// challenge/response loop
	for {
		response, err := h.attest(attestStream, request)
		if err != nil {
			h.c.Log.WithError(err).Error("Failed to attest")
			return nil, errorutil.WrapError(err, "failed to attest")
		}
		if response.Challenge == nil {
			return response, nil
		}

		challengeResponse := &node.AttestResponse{
			Challenge: response.Challenge,
		}

		if err := nodeStream.Send(challengeResponse); err != nil {
			h.c.Log.WithError(err).Error("Failed to send challenge request")
			return nil, errorutil.WrapError(err, "failed to send challenge request")
		}

		request, err = nodeStream.Recv()
		if err != nil {
			h.c.Log.WithError(err).Error("Failed to receive challenge response")
			return nil, errorutil.WrapError(err, "failed to receive challenge response")
		}
	}
}

func (h *Handler) attest(attestStream nodeattestor.NodeAttestor_AttestClient, nodeRequest *node.AttestRequest) (*nodeattestor.AttestResponse, error) {
	attestRequest := &nodeattestor.AttestRequest{
		AttestationData: nodeRequest.AttestationData,
		Response:        nodeRequest.Response,
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
		h.c.Log.WithError(err).Error("Failed to determine if agent has already attested")
		return nil, errorutil.WrapError(err, "failed to determine if agent has already attested")
	case attestedBefore:
		return nil, errors.New("join token does not exist or has already been used")
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

func (h *Handler) updateAttestedNode(ctx context.Context, req *datastore.UpdateAttestedNodeRequest) error {
	ds := h.c.Catalog.GetDataStore()
	if _, err := ds.UpdateAttestedNode(ctx, req); err != nil {
		return fmt.Errorf("failed to update attested node %q: %v", req.SpiffeId, err)
	}

	return nil
}

func (h *Handler) createAttestationEntry(ctx context.Context, cert *x509.Certificate, attestationType string) error {
	ds := h.c.Catalog.GetDataStore()
	return createAttestationEntry(ctx, ds, cert, attestationType)
}

func (h *Handler) updateNodeSelectors(ctx context.Context, baseSpiffeID string, attestResponse *nodeattestor.AttestResponse, attestationType string) error {
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
		h.c.Log.WithField(telemetry.Attestor, attestationType).Debug("Could not find node resolver")
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

func (h *Handler) getAttestResponse(ctx context.Context, baseSpiffeID string, svid []*x509.Certificate) (*node.AttestResponse, error) {
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

	h.c.Log.WithField(telemetry.CallerID, callerID).Error("Unauthorized downstream workload")
	return nil, errors.New("unauthorized downstream workload")
}

func (h *Handler) signCSRs(ctx context.Context, peerCert *x509.Certificate, csrs map[string][]byte, regEntries []*common.RegistrationEntry) (map[string]*node.X509SVID, error) {
	if len(csrs) == 0 {
		return nil, nil
	}

	callerID, err := getSpiffeIDFromCert(peerCert)
	if err != nil {
		return nil, err
	}

	//convert registration entries into a map for easy lookup
	regEntriesMap := make(map[string]*common.RegistrationEntry)
	for _, entry := range regEntries {
		regEntriesMap[entry.EntryId] = entry
	}

	ds := h.c.Catalog.GetDataStore()
	svids := make(map[string]*node.X509SVID)
	//iterate the CSRs and sign them
	for entryID, csrBytes := range csrs {
		csr, err := h.parseCSR(csrBytes, idutil.AllowAny())
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
			svids[entryID] = svid

			req := &datastore.UpdateAttestedNodeRequest{
				SpiffeId:            res.Node.SpiffeId,
				CertNotAfter:        res.Node.CertNotAfter,
				CertSerialNumber:    res.Node.CertSerialNumber,
				NewCertNotAfter:     svidCert.NotAfter.Unix(),
				NewCertSerialNumber: svidCert.SerialNumber.String(),
			}

			if err := h.updateAttestedNode(ctx, req); err != nil {
				return nil, err
			}
		} else {
			signLog.Debug("Signing SVID")
			svid, err := h.buildSVID(ctx, entryID, csr, regEntriesMap)
			if err != nil {
				return nil, err
			}
			svids[entryID] = svid
		}
	}

	return svids, nil
}

func (h *Handler) buildSVID(ctx context.Context, id string, csr *CSR, regEntries map[string]*common.RegistrationEntry) (*node.X509SVID, error) {
	entry, ok := regEntries[id]
	if !ok {
		var idType string
		if strings.HasPrefix(id, "spiffe://") {
			idType = telemetry.SPIFFEID
		} else {
			idType = telemetry.RegistrationID
		}
		h.c.Log.WithFields(logrus.Fields{
			telemetry.IDType: idType,
			idType:           id,
		}).Error("Not entitled to sign CSR for given ID type")
		return nil, errors.New("not entitled to sign CSR for given ID type")
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

// getBundle fetches a bundle from the datastore, by trust domain, using a cache.
func (h *Handler) getBundle(ctx context.Context, trustDomainID string) (*common.Bundle, error) {
	ds := h.c.Catalog.GetDataStore()
	resp, err := ds.FetchBundle(dscache.WithCache(ctx), &datastore.FetchBundleRequest{
		TrustDomainId: trustDomainID,
	})
	if err != nil {
		h.c.Log.WithError(err).Error("Failed to fetch bundle")
		return nil, errorutil.WrapError(err, "failed to fetch bundle")
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
		return h.parseCSR(csrBytes, idutil.AllowAnyInTrustDomain(h.c.TrustDomain.Host))
	}
	return h.parseCSR(csrBytes, idutil.AllowTrustDomainAgent(h.c.TrustDomain.Host))
}

func (h *Handler) parseX509CACSR(csrBytes []byte) (*CSR, error) {
	csr, err := h.parseCSR(csrBytes, idutil.AllowTrustDomain(h.c.TrustDomain.Host))
	if err != nil {
		return nil, err
	}
	if csr.SpiffeID == "" {
		return nil, errors.New("X509 CA CSR is missing the SPIFFE ID") //nolint: golint // leading cap on error is ok
	}
	return csr, nil
}

func (h *Handler) parseCSR(csrBytes []byte, mode idutil.ValidationMode) (*CSR, error) {
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		h.c.Log.WithError(err).Error("Failed to parse CSR")
		return nil, errorutil.WrapError(err, "failed to parse CSR")
	}

	var spiffeID string
	switch len(csr.URIs) {
	case 0:
	case 1:
		spiffeID, err = idutil.NormalizeSpiffeID(csr.URIs[0].String(), mode)
		if err != nil {
			h.c.Log.WithError(err).Error("Invalid SPIFFE ID in CSR")
			return nil, errorutil.WrapError(err, "invalid SPIFFE ID in CSR")
		}
	default:
		return nil, errors.New("CSR cannot have more than one URI SAN")
	}

	return &CSR{
		SpiffeID:  spiffeID,
		PublicKey: csr.PublicKey,
	}, nil
}

func (h *Handler) isBanned(ctx context.Context, agentID string) (bool, error) {
	ds := h.c.Catalog.GetDataStore()

	resp, err := ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{
		SpiffeId: agentID,
	})
	if err != nil {
		return false, fmt.Errorf("failed to fetch attested node: %v", err)
	}

	if resp.Node == nil {
		// agent not found
		return false, nil
	}

	return nodeutil.IsAgentBanned(resp.Node), nil
}

func getPeerCertificateFromRequestContext(ctx context.Context) (*x509.Certificate, error) {
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

// Gets the SPIFFE ID from a cert or returns an empty string if there is an error.
func tryGetSpiffeIDFromCert(cert *x509.Certificate) string {
	spiffeid, _ := getSpiffeIDFromCert(cert)
	return spiffeid
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
