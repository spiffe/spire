package api

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	workloadattestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/agent/broker/brokercontext"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/common/hintsfilter"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/telemetry/agent/adminapi"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

// RegisterService registers the SPIFFE Broker API service on the provided server.
func RegisterService(s *grpc.Server, service *Service) {
	broker.RegisterAPIServer(s, service)
}

type Config struct {
	Log      logrus.FieldLogger
	Metrics  telemetry.Metrics
	Manager  manager.Manager
	Attestor workloadattestor.Attestor

	// AllowedReferenceTypesByCaller restricts which WorkloadReference type
	// URLs each authenticated caller (broker SPIFFE ID) may use and whether
	// each type is also allowed over TCP. A caller missing from the map has
	// no restriction over UDS, but remains denied over TCP.
	AllowedReferenceTypesByCaller map[spiffeid.ID]ReferenceTypePolicy
}

func New(config Config) *Service {
	return &Service{
		manager:                       config.Manager,
		peerAttestor:                  config.Attestor,
		metrics:                       config.Metrics,
		allowedReferenceTypesByCaller: config.AllowedReferenceTypesByCaller,
	}
}

// ReferenceTypeAccess describes how a broker may use a WorkloadReference type.
type ReferenceTypeAccess struct {
	AllowOverTCP bool
}

// ReferenceTypePolicy is the per-broker WorkloadReference type policy.
type ReferenceTypePolicy struct {
	AllowAny        bool
	AllowAnyOverTCP bool
	Types           map[string]ReferenceTypeAccess
}

func (p ReferenceTypePolicy) AccessFor(typeURL string) (ReferenceTypeAccess, bool) {
	if p.AllowAny {
		return ReferenceTypeAccess{AllowOverTCP: p.AllowAnyOverTCP}, true
	}
	access, ok := p.Types[typeURL]
	return access, ok
}

// Service implements the SPIFFE Broker API server.
type Service struct {
	broker.UnimplementedAPIServer

	manager                       manager.Manager
	peerAttestor                  workloadattestor.Attestor
	metrics                       telemetry.Metrics
	allowedReferenceTypesByCaller map[spiffeid.ID]ReferenceTypePolicy
}

// authorizeReferenceType applies the per-broker reference type policy. UDS
// requests only need the type to be allowed. TCP requests additionally need
// that same allowed type to opt in to TCP use.
func (s *Service) authorizeReferenceType(ctx context.Context, caller spiffeid.ID, ref *anypb.Any) error {
	// Reject malformed requests before the allowlist gates so a missing or
	// empty reference yields InvalidArgument rather than PermissionDenied.
	if ref.GetTypeUrl() == "" {
		return status.Error(codes.InvalidArgument, "workload reference must be provided")
	}

	policy, ok := s.allowedReferenceTypesByCaller[caller]
	if ok {
		access, ok := policy.AccessFor(ref.GetTypeUrl())
		if !ok {
			return status.Errorf(codes.PermissionDenied, "broker %q is not allowed to use reference type %q", caller, ref.GetTypeUrl())
		}
		if isTCPCaller(ctx) && !access.AllowOverTCP {
			return status.Errorf(codes.PermissionDenied, "reference type %q is not allowed over TCP for broker %q", ref.GetTypeUrl(), caller)
		}
		return nil
	}
	if isTCPCaller(ctx) {
		return status.Errorf(codes.PermissionDenied, "reference type %q is not allowed over TCP for broker %q", ref.GetTypeUrl(), caller)
	}
	return nil
}

// isTCPCaller reports whether the incoming gRPC connection is over TCP
// (as opposed to a Unix domain socket).
func isTCPCaller(ctx context.Context) bool {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return false
	}
	_, tcp := p.Addr.(*net.TCPAddr)
	return tcp
}

func (s *Service) getCallerContext(ctx context.Context) (spiffeid.ID, error) {
	// The broker endpoint configures the gRPC server with plain
	// credentials.NewTLS (to keep SessionTicketsDisabled and TLS policy
	// customizations on the *tls.Config). That credentials wrapper exposes
	// the peer SPIFFE ID via credentials.TLSInfo rather than go-spiffe's
	// grpccredentials authInfo, so we extract it ourselves here.
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return spiffeid.ID{}, status.Error(codes.Unauthenticated, "unable to determine caller identity")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || tlsInfo.SPIFFEID == nil {
		return spiffeid.ID{}, status.Error(codes.Unauthenticated, "unable to determine caller identity")
	}
	id, err := spiffeid.FromString(tlsInfo.SPIFFEID.String())
	if err != nil {
		return spiffeid.ID{}, status.Errorf(codes.Unauthenticated, "invalid caller SPIFFE ID: %v", err)
	}
	return id, nil
}

func (s *Service) SubscribeToX509SVID(req *broker.SubscribeToX509SVIDRequest, stream broker.API_SubscribeToX509SVIDServer) error {
	latency := adminapi.StartFirstX509SVIDUpdateLatency(s.metrics)
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)
	var receivedFirstUpdate bool

	peer, err := s.getCallerContext(ctx)
	if err != nil {
		return err
	}
	log = log.WithField("broker_peer", peer.String())

	if err := s.authorizeReferenceType(ctx, peer, req.GetReference().GetReference()); err != nil {
		return err
	}

	selectors, err := s.constructValidSelectorsFromReference(brokercontext.WithCallerID(ctx, peer), log, req.Reference)
	if err != nil {
		return err
	}

	log.WithField(telemetry.Selectors, selectors).Debug("Subscribing to cache changes")

	subscriber, err := s.manager.SubscribeToCacheChanges(ctx, selectors)
	if err != nil {
		log.WithError(err).Error("Subscribe to cache changes failed")
		return err
	}
	defer subscriber.Finish()

	for {
		select {
		case update := <-subscriber.Updates():
			update.Identities = hintsfilter.FilterIdentities(update.Identities, log)
			if len(update.Identities) > 0 && !receivedFirstUpdate {
				// emit latency metric for first update containing an SVID.
				latency.Measure()
				receivedFirstUpdate = true
			}

			if err := sendX509SVIDResponse(update, stream, log); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (s *Service) SubscribeToX509Bundles(req *broker.SubscribeToX509BundlesRequest, stream broker.API_SubscribeToX509BundlesServer) error {
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)

	peer, err := s.getCallerContext(ctx)
	if err != nil {
		return err
	}
	log = log.WithField("broker_peer", peer.String())

	if err := s.authorizeReferenceType(ctx, peer, req.GetReference().GetReference()); err != nil {
		return err
	}

	// The bundle response is workload-independent, but per the SPIFFE Broker
	// API spec the request still identifies a workload. Validate the reference
	// resolves so a caller can't pull bundles for workloads it can't attest.
	if _, err := s.constructValidSelectorsFromReference(brokercontext.WithCallerID(ctx, peer), log, req.Reference); err != nil {
		return err
	}

	subscriber := s.manager.SubscribeToBundleChanges()

	send := func(bundles map[spiffeid.TrustDomain]*cache.Bundle) error {
		// Rebuild the map each tick — Next()/Value() return the full set of
		// trust domains, so reusing the previous map would leave entries for
		// trust domains that have since been removed.
		caCerts := make(map[string][]byte, len(bundles))
		for td, bundle := range bundles {
			caCerts[td.IDString()] = marshalBundle(bundle.X509Authorities())
		}
		return stream.Send(&broker.SubscribeToX509BundlesResponse{Bundles: caCerts})
	}

	if err := send(subscriber.Value()); err != nil {
		return err
	}

	for {
		select {
		case <-subscriber.Changes():
			if err := send(subscriber.Next()); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (s *Service) FetchJWTSVID(ctx context.Context, req *broker.FetchJWTSVIDRequest) (*broker.FetchJWTSVIDResponse, error) {
	log := rpccontext.Logger(ctx)
	if len(req.Audience) == 0 {
		log.Error("Missing required audience parameter")
		return nil, status.Error(codes.InvalidArgument, "audience must be specified")
	}

	peer, err := s.getCallerContext(ctx)
	if err != nil {
		return nil, err
	}
	log = log.WithField("broker_peer", peer.String())

	if err := s.authorizeReferenceType(ctx, peer, req.GetReference().GetReference()); err != nil {
		return nil, err
	}

	selectors, err := s.constructValidSelectorsFromReference(brokercontext.WithCallerID(ctx, peer), log, req.Reference)
	if err != nil {
		return nil, err
	}

	resp := new(broker.FetchJWTSVIDResponse)
	entries := s.manager.MatchingRegistrationEntries(selectors)
	entries = hintsfilter.FilterRegistrations(entries, log)
	for _, entry := range entries {
		spiffeID, err := spiffeid.FromString(entry.SpiffeId)
		if err != nil {
			log.WithField(telemetry.SPIFFEID, entry.SpiffeId).WithError(err).Error("Invalid requested SPIFFE ID")
			return nil, status.Errorf(codes.InvalidArgument, "invalid requested SPIFFE ID: %v", err)
		}

		loopLog := log.WithField(telemetry.SPIFFEID, spiffeID.String())

		var svid *client.JWTSVID
		svid, err = s.manager.FetchJWTSVID(ctx, entry, req.Audience)
		if err != nil {
			loopLog.WithError(err).Error("Could not fetch JWT-SVID")
			return nil, status.Errorf(codes.Unavailable, "could not fetch JWT-SVID: %v", err)
		}
		resp.Svids = append(resp.Svids, &broker.JWTSVID{
			SpiffeId: spiffeID.String(),
			Hint:     entry.Hint,
			Svid:     svid.Token,
		})

		ttl := time.Until(svid.ExpiresAt)
		loopLog.WithField(telemetry.TTL, ttl.Seconds()).Debug("Fetched JWT SVID")
	}

	if len(resp.Svids) == 0 {
		log.Error("No identity issued")
		return nil, status.Error(codes.PermissionDenied, "no identity issued")
	}

	return resp, nil
}

func (s *Service) SubscribeToJWTBundles(req *broker.SubscribeToJWTBundlesRequest, stream broker.API_SubscribeToJWTBundlesServer) error {
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)

	peer, err := s.getCallerContext(ctx)
	if err != nil {
		return err
	}
	log = log.WithField("broker_peer", peer.String())

	if err := s.authorizeReferenceType(ctx, peer, req.GetReference().GetReference()); err != nil {
		return err
	}

	// The bundle response is workload-independent, but per the SPIFFE Broker
	// API spec the request still identifies a workload. Validate the reference
	// resolves so a caller can't pull bundles for workloads it can't attest.
	if _, err := s.constructValidSelectorsFromReference(brokercontext.WithCallerID(ctx, peer), log, req.Reference); err != nil {
		return err
	}

	subscriber := s.manager.SubscribeToBundleChanges()

	send := func(bundles map[spiffeid.TrustDomain]*cache.Bundle) error {
		// Rebuild the map each tick — Next()/Value() return the full set of
		// trust domains, so reusing the previous map would leave entries for
		// trust domains that have since been removed.
		jwtbundles := make(map[string][]byte, len(bundles))
		for td, bundle := range bundles {
			jwksBytes, err := bundleutil.Marshal(bundle, bundleutil.NoX509SVIDKeys(), bundleutil.StandardJWKS())
			if err != nil {
				return err
			}
			jwtbundles[td.IDString()] = jwksBytes
		}
		return stream.Send(&broker.SubscribeToJWTBundlesResponse{Bundles: jwtbundles})
	}

	if err := send(subscriber.Value()); err != nil {
		return err
	}

	for {
		select {
		case <-subscriber.Changes():
			if err := send(subscriber.Next()); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (s *Service) constructValidSelectorsFromReference(ctx context.Context, log logrus.FieldLogger, ref *broker.WorkloadReference) ([]*common.Selector, error) {
	if ref == nil {
		log.Error("No workload reference provided")
		return nil, status.Error(codes.InvalidArgument, "workload reference must be provided")
	}

	selectors, err := s.peerAttestor.AttestReference(ctx, ref.Reference)
	if err != nil {
		log.WithError(err).Error("Workload attestation failed")
		// Preserve the plugin's status (InvalidArgument, NotFound,
		// PermissionDenied, etc.); only opaque errors are wrapped as
		// Unauthenticated.
		if _, ok := status.FromError(err); ok {
			return nil, err
		}
		return nil, status.Errorf(codes.Unauthenticated, "workload attestation failed: %v", err)
	}

	return selectors, nil
}

func sendX509SVIDResponse(update *cache.WorkloadUpdate, stream broker.API_SubscribeToX509SVIDServer, log logrus.FieldLogger) (err error) {
	resp, notAfters, err := composeX509SVIDBySelectors(update)
	if err != nil {
		log.WithError(err).Error("Could not serialize X.509 SVID response")
		return status.Error(codes.Internal, "could not serialize response")
	}

	if err := stream.Send(resp); err != nil {
		log.WithError(err).Error("Failed to send X.509 SVID response")
		return err
	}

	log = log.WithField(telemetry.Count, len(resp.Svids))

	// log details on each SVID
	// a response has already been sent so nothing is
	// blocked on this logic
	for i, svid := range resp.Svids {
		ttl := time.Until(notAfters[i])
		log.WithFields(logrus.Fields{
			telemetry.SPIFFEID: svid.SpiffeId,
			telemetry.TTL:      ttl.Seconds(),
		}).Debug("Fetched X.509 SVID for broker")
	}

	return nil
}

func composeX509SVIDBySelectors(update *cache.WorkloadUpdate) (*broker.SubscribeToX509SVIDResponse, []time.Time, error) {
	resp := new(broker.SubscribeToX509SVIDResponse)
	resp.Svids = make([]*broker.X509SVID, 0, len(update.Identities))
	resp.FederatedBundles = make(map[string][]byte, len(update.FederatedBundles))
	notAfters := make([]time.Time, 0, len(update.Identities))

	x509Bundle := marshalBundle(update.Bundle.X509Authorities())
	for _, identity := range update.Identities {
		// Do not send admin nor downstream SVIDs to the caller
		if identity.Entry.Admin || identity.Entry.Downstream {
			continue
		}

		// check if SVIDs exist for the identity
		if len(identity.SVID) == 0 {
			return nil, nil, errors.New("unable to get SVID from identity")
		}

		id, err := spiffeid.FromString(identity.Entry.SpiffeId)
		if err != nil {
			return nil, nil, fmt.Errorf("error during SPIFFE ID parsing: %w", err)
		}

		keyData, err := x509.MarshalPKCS8PrivateKey(identity.PrivateKey)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal key for %v: %w", id, err)
		}

		svid := &broker.X509SVID{
			SpiffeId:    id.String(),
			X509Svid:    x509util.DERFromCertificates(identity.SVID),
			Bundle:      x509Bundle,
			Hint:        identity.Entry.Hint,
			X509SvidKey: keyData,
		}
		resp.Svids = append(resp.Svids, svid)
		notAfters = append(notAfters, identity.SVID[0].NotAfter)
	}

	for td, bundle := range update.FederatedBundles {
		resp.FederatedBundles[td.IDString()] = marshalBundle(bundle.X509Authorities())
	}

	return resp, notAfters, nil
}

func marshalBundle(certs []*x509.Certificate) []byte {
	bundle := []byte{}
	for _, c := range certs {
		bundle = append(bundle, c.Raw...)
	}
	return bundle
}
