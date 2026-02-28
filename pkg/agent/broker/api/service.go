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
	"github.com/spiffe/spire-api-sdk/proto/spiffe/broker"
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
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RegisterService registers the delegated identity service on the provided server
func RegisterService(s *grpc.Server, service *Service) {
	broker.RegisterAPIServer(s, service)
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
	broker.UnimplementedAPIServer

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

func (s *Service) SubscribeToX509SVID(req *broker.SubscribeToX509SVIDRequest, stream broker.API_SubscribeToX509SVIDServer) error {
	latency := adminapi.StartFirstX509SVIDUpdateLatency(s.metrics)
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)
	var receivedFirstUpdate bool

	// peer, err := s.getCallerContext(ctx)
	// if err != nil {
	// 	return err
	// }
	// log = log.WithField("broker_peer", peer.String())

	selectors, err := s.constructValidSelectorsFromReference(ctx, log, req.Reference)
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

func (s *Service) SubscribeToX509Bundles(_ *broker.SubscribeToX509BundlesRequest, stream broker.API_SubscribeToX509BundlesServer) error {
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

	resp := &broker.SubscribeToX509BundlesResponse{
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

			resp := &broker.SubscribeToX509BundlesResponse{
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

	selectors, err := s.constructValidSelectorsFromReference(ctx, log, req.Reference)
	if err != nil {
		return nil, err
	}

	resp := new(broker.FetchJWTSVIDResponse)
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

func (s *Service) SubscribeToJWTBundles(_ *broker.SubscribeToJWTBundlesRequest, stream broker.API_SubscribeToJWTBundlesServer) error {
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

	resp := &broker.SubscribeToJWTBundlesResponse{
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

			resp := &broker.SubscribeToJWTBundlesResponse{
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

func (s *Service) constructValidSelectorsFromReference(ctx context.Context, log logrus.FieldLogger, ref *broker.WorkloadReference) ([]*common.Selector, error) {
	if ref == nil {
		log.Error("No workload reference provided")
		return nil, status.Error(codes.InvalidArgument, "workload reference must be provided")
	}

	selectors, err := s.peerAttestor.AttestReference(ctx, ref.Reference)
	if err != nil {
		log.WithError(err).Error("Workload attestation failed")
		return nil, status.Errorf(codes.Unauthenticated, "workload attestation failed: %v", err)
	}

	return selectors, nil
}

func sendX509SVIDResponse(update *cache.WorkloadUpdate, stream broker.API_SubscribeToX509SVIDServer, log logrus.FieldLogger) (err error) {
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

func composeX509SVIDBySelectors(update *cache.WorkloadUpdate) (*broker.SubscribeToX509SVIDResponse, error) {
	resp := new(broker.SubscribeToX509SVIDResponse)
	resp.Svids = make([]*broker.X509SVID, 0, len(update.Identities))
	resp.FederatedBundles = make(map[string][]byte, len(update.FederatedBundles))

	x509Bundle := marshalBundle(update.Bundle.X509Authorities())
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

		svid := &broker.X509SVID{
			SpiffeId:    id.String(),
			X509Svid:    x509util.DERFromCertificates(identity.SVID),
			Bundle:      x509Bundle,
			Hint:        identity.Entry.Hint,
			X509SvidKey: keyData,
		}
		resp.Svids = append(resp.Svids, svid)
	}

	for td, bundle := range update.FederatedBundles {
		resp.FederatedBundles[td.IDString()] = marshalBundle(bundle.X509Authorities())
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
