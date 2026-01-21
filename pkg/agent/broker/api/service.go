package api

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	workloadattestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/telemetry/agent/adminapi"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/brokerapi"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RegisterService registers the delegated identity service on the provided server
func RegisterService(s *grpc.Server, service *Service) {
	brokerapi.RegisterSpiffeBrokerAPIServer(s, service)
}

type Config struct {
	Log      logrus.FieldLogger
	Metrics  telemetry.Metrics
	Manager  manager.Manager
	Attestor workloadattestor.Attestor
}

func New(config Config) *Service {
	return &Service{
		manager:      config.Manager,
		peerAttestor: config.Attestor,
		metrics:      config.Metrics,
	}
}

// Service implements the delegated identity server
type Service struct {
	brokerapi.UnimplementedSpiffeBrokerAPIServer

	manager      manager.Manager
	peerAttestor workloadattestor.Attestor
	metrics      telemetry.Metrics
}

func (s *Service) getCallerContext(ctx context.Context) (spiffeid.ID, error) {
	peer, ok := grpccredentials.PeerIDFromContext(ctx)
	if !ok {
		return spiffeid.ID{}, status.Error(codes.Unauthenticated, "unable to determine caller identity")
	}
	return peer, nil
}

func (s *Service) FetchX509SVID(req *brokerapi.X509SVIDRequest, stream brokerapi.SpiffeBrokerAPI_FetchX509SVIDServer) error {
	latency := adminapi.StartFirstX509SVIDUpdateLatency(s.metrics)
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)
	var receivedFirstUpdate bool

	peer, err := s.getCallerContext(ctx)
	if err != nil {
		return err
	}
	log = log.WithField("broker_peer", peer.String())

	selectors, err := s.constructValidSelectorsFromReferences(ctx, log, req.References)
	if err != nil {
		return err
	}

	log.WithFields(logrus.Fields{
		"request_selectors": selectors,
	}).Debug("Subscribing to cache changes")

	subscriber, err := s.manager.SubscribeToCacheChanges(ctx, selectors)
	if err != nil {
		log.WithError(err).Error("Subscribe to cache changes failed")
		return err
	}
	defer subscriber.Finish()

	for {
		select {
		case update := <-subscriber.Updates():
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

func (s *Service) FetchX509Bundles(_ *brokerapi.X509BundlesRequest, stream brokerapi.SpiffeBrokerAPI_FetchX509BundlesServer) error {
	ctx := stream.Context()

	peer, err := s.getCallerContext(ctx)
	if err != nil {
		return err
	}
	_ = rpccontext.Logger(ctx).WithField("broker_peer", peer.String())

	subscriber := s.manager.SubscribeToBundleChanges()

	// send initial update....
	caCerts := make(map[string][]byte)
	for td, bundle := range subscriber.Value() {
		caCerts[td.IDString()] = marshalBundle(bundle.X509Authorities())
	}

	resp := &brokerapi.X509BundlesResponse{
		Bundles: caCerts,
	}

	if err := stream.Send(resp); err != nil {
		return err
	}

	for {
		select {
		case <-subscriber.Changes():
			for td, bundle := range subscriber.Next() {
				caCerts[td.IDString()] = marshalBundle(bundle.X509Authorities())
			}

			resp := &brokerapi.X509BundlesResponse{
				Bundles: caCerts,
			}

			if err := stream.Send(resp); err != nil {
				return err
			}

		case <-ctx.Done():
			return nil
		}
	}
}

func (s *Service) FetchJWTSVID(ctx context.Context, req *brokerapi.JWTSVIDRequest) (*brokerapi.JWTSVIDResponse, error) {
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

	selectors, err := s.constructValidSelectorsFromReferences(ctx, log, req.References)
	if err != nil {
		return nil, err
	}

	resp := new(brokerapi.JWTSVIDResponse)
	entries := s.manager.MatchingRegistrationEntries(selectors)
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
		resp.Svids = append(resp.Svids, &brokerapi.JWTSVID{
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

func (s *Service) FetchJWTBundles(_ *brokerapi.JWTBundlesRequest, stream brokerapi.SpiffeBrokerAPI_FetchJWTBundlesServer) error {
	ctx := stream.Context()

	peer, err := s.getCallerContext(ctx)
	if err != nil {
		return err
	}
	_ = rpccontext.Logger(ctx).WithField("broker_peer", peer.String())

	subscriber := s.manager.SubscribeToBundleChanges()

	// send initial update....
	jwtbundles := make(map[string][]byte)
	for td, bundle := range subscriber.Value() {
		jwksBytes, err := bundleutil.Marshal(bundle, bundleutil.NoX509SVIDKeys(), bundleutil.StandardJWKS())
		if err != nil {
			return err
		}
		jwtbundles[td.IDString()] = jwksBytes
	}

	resp := &brokerapi.JWTBundlesResponse{
		Bundles: jwtbundles,
	}

	if err := stream.Send(resp); err != nil {
		return err
	}
	for {
		select {
		case <-subscriber.Changes():
			for td, bundle := range subscriber.Next() {
				jwksBytes, err := bundleutil.Marshal(bundle, bundleutil.NoX509SVIDKeys(), bundleutil.StandardJWKS())
				if err != nil {
					return err
				}
				jwtbundles[td.IDString()] = jwksBytes
			}

			resp := &brokerapi.JWTBundlesResponse{
				Bundles: jwtbundles,
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (s *Service) constructValidSelectorsFromReferences(ctx context.Context, log logrus.FieldLogger, refs []*brokerapi.WorkloadReference) ([]*common.Selector, error) {
	if len(refs) == 0 {
		log.Error("No workload references provided")
		return nil, status.Error(codes.InvalidArgument, "no workload references provided")
	}

	if len(refs) > 1 {
		log.Error("Multiple workload references provided; only one is supported")
		return nil, status.Error(codes.InvalidArgument, "multiple workload references provided; SPIRE only supports one at the moment")
	}

	switch refs[0].Reference.TypeUrl {
	case "type.googleapis.com/brokerapi.WorkloadPIDReference":
		var pidRef brokerapi.WorkloadPIDReference
		if err := refs[0].Reference.UnmarshalTo(&pidRef); err != nil {
			log.WithError(err).Error("Failed to unmarshal PID workload reference")
			return nil, status.Error(codes.InvalidArgument, "failed to unmarshal PID workload reference")
		}

		selectors, err := s.peerAttestor.Attest(ctx, int(pidRef.Pid))
		if err != nil {
			log.WithError(err).Error("Workload attestation with PID failed")
			return nil, status.Error(codes.Internal, "workload attestation with PID failed")
		}
		return selectors, nil
	default:
		log.WithField("type_url", refs[0].Reference.TypeUrl).Error("Unsupported workload reference type")
		return nil, status.Error(codes.InvalidArgument, "unsupported workload reference type")
	}
}

func sendX509SVIDResponse(update *cache.WorkloadUpdate, stream brokerapi.SpiffeBrokerAPI_FetchX509SVIDServer, log logrus.FieldLogger) (err error) {
	resp, err := composeX509SVIDBySelectors(update)
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
		// Ideally ID Proto parsing should succeed, but if it fails,
		// ignore the error and still log with empty spiffe_id.
		ttl := time.Until(update.Identities[i].SVID[0].NotAfter)
		log.WithFields(logrus.Fields{
			telemetry.SPIFFEID: svid.SpiffeId,
			telemetry.TTL:      ttl.Seconds(),
		}).Debug("Fetched X.509 SVID for broker")
	}

	return nil
}

func composeX509SVIDBySelectors(update *cache.WorkloadUpdate) (*brokerapi.X509SVIDResponse, error) {
	resp := new(brokerapi.X509SVIDResponse)
	resp.Svids = make([]*brokerapi.X509SVID, 0, len(update.Identities))

	for _, identity := range update.Identities {
		// Do not send admin nor downstream SVIDs to the caller
		if identity.Entry.Admin || identity.Entry.Downstream {
			continue
		}

		// check if SVIDs exist for the identity
		if len(identity.SVID) == 0 {
			return nil, errors.New("unable to get SVID from identity")
		}

		id, err := idutil.IDProtoFromString(identity.Entry.SpiffeId)
		if err != nil {
			return nil, fmt.Errorf("error during SPIFFE ID parsing: %w", err)
		}

		keyData, err := x509.MarshalPKCS8PrivateKey(identity.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("marshal key for %v: %w", id, err)
		}

		svid := &brokerapi.X509SVID{
			SpiffeId: id.String(),
			X509Svid: x509util.DERFromCertificates(identity.SVID),
			// TODO(arndt): what about bundle?
			Hint:        identity.Entry.Hint,
			X509SvidKey: keyData,
		}
		resp.Svids = append(resp.Svids, svid)
	}
	return resp, nil
}

func marshalBundle(certs []*x509.Certificate) []byte {
	bundle := []byte{}
	for _, c := range certs {
		bundle = append(bundle, c.Raw...)
	}
	return bundle
}
