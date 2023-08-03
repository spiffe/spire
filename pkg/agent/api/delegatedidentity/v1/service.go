package delegatedidentity

import (
	"context"
	"crypto/x509"
	"fmt"
	"sort"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	delegatedidentityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	workloadattestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/endpoints"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/telemetry/agent/adminapi"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RegisterService registers the delegated identity service on the provided server
func RegisterService(s *grpc.Server, service *Service) {
	delegatedidentityv1.RegisterDelegatedIdentityServer(s, service)
}

type attestor interface {
	Attest(ctx context.Context) ([]*common.Selector, error)
}

type Config struct {
	Log                 logrus.FieldLogger
	Metrics             telemetry.Metrics
	Manager             manager.Manager
	Attestor            workloadattestor.Attestor
	AuthorizedDelegates []string
}

func New(config Config) *Service {
	AuthorizedDelegates := map[string]bool{}

	for _, delegate := range config.AuthorizedDelegates {
		AuthorizedDelegates[delegate] = true
	}

	return &Service{
		manager:             config.Manager,
		attestor:            endpoints.PeerTrackerAttestor{Attestor: config.Attestor},
		metrics:             config.Metrics,
		authorizedDelegates: AuthorizedDelegates,
	}
}

// Service implements the delegated identity server
type Service struct {
	delegatedidentityv1.UnsafeDelegatedIdentityServer

	manager  manager.Manager
	attestor attestor
	metrics  telemetry.Metrics

	// SPIFFE IDs of delegates that are authorized to use this API
	authorizedDelegates map[string]bool
}

// isCallerAuthorized attests the caller based on the authorized delegates map.
func (s *Service) isCallerAuthorized(ctx context.Context, log logrus.FieldLogger, cachedSelectors []*common.Selector) ([]*common.Selector, error) {
	var err error
	callerSelectors := cachedSelectors

	if callerSelectors == nil {
		callerSelectors, err = s.attestor.Attest(ctx)
		if err != nil {
			log.WithError(err).Error("Workload attestation failed")
			return nil, status.Error(codes.Internal, "workload attestation failed")
		}
	}

	log = log.WithField("delegate_selectors", callerSelectors)
	entries := s.manager.MatchingRegistrationEntries(callerSelectors)
	numRegisteredEntries := len(entries)

	if numRegisteredEntries == 0 {
		log.Error("no identity issued")
		return nil, status.Error(codes.PermissionDenied, "no identity issued")
	}

	for _, entry := range entries {
		if _, ok := s.authorizedDelegates[entry.SpiffeId]; ok {
			log.WithField("delegate_id", entry.SpiffeId).Debug("Caller authorized as delegate")
			return callerSelectors, nil
		}
	}

	// caller has identity associated with but none is authorized
	log.WithFields(logrus.Fields{
		"num_registered_entries": numRegisteredEntries,
		"default_id":             entries[0].SpiffeId,
	}).Error("Permission denied; caller not configured as an authorized delegate.")

	return nil, status.Error(codes.PermissionDenied, "caller not configured as an authorized delegate")
}

func (s *Service) SubscribeToX509SVIDs(req *delegatedidentityv1.SubscribeToX509SVIDsRequest, stream delegatedidentityv1.DelegatedIdentity_SubscribeToX509SVIDsServer) error {
	latency := adminapi.StartFirstX509SVIDUpdateLatency(s.metrics)
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)
	var receivedFirstUpdate bool

	cachedSelectors, err := s.isCallerAuthorized(ctx, log, nil)
	if err != nil {
		return err
	}

	selectors, err := api.SelectorsFromProto(req.Selectors)
	if err != nil {
		log.WithError(err).Error("Invalid argument; could not parse provided selectors")
		return status.Error(codes.InvalidArgument, "could not parse provided selectors")
	}

	log.WithFields(logrus.Fields{
		"delegate_selectors": cachedSelectors,
		"request_selectors":  selectors,
	}).Info("Subscribing to cache changes")

	subscriber, err := s.manager.SubscribeToCacheChanges(ctx, selectors)
	if err != nil {
		log.WithError(err).Error("Subscribe to cache changes failed")
		return err
	}
	defer subscriber.Finish()

	for {
		select {
		case update := <-subscriber.Updates():
			if !receivedFirstUpdate {
				// emit latency metric for first update.
				latency.Measure()
				receivedFirstUpdate = true
			}

			if _, err := s.isCallerAuthorized(ctx, log, cachedSelectors); err != nil {
				return err
			}

			if err := sendX509SVIDResponse(update, stream, log); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func sendX509SVIDResponse(update *cache.WorkloadUpdate, stream delegatedidentityv1.DelegatedIdentity_SubscribeToX509SVIDsServer, log logrus.FieldLogger) (err error) {
	resp, err := composeX509SVIDBySelectors(update)
	if err != nil {
		log.WithError(err).Error("Could not serialize X.509 SVID response")
		return status.Error(codes.Internal, "could not serialize response")
	}

	if err := stream.Send(resp); err != nil {
		log.WithError(err).Error("Failed to send X.509 SVID response")
		return err
	}

	log = log.WithField(telemetry.Count, len(resp.X509Svids))

	// log details on each SVID
	// a response has already been sent so nothing is
	// blocked on this logic
	for i, svid := range resp.X509Svids {
		ttl := time.Until(update.Identities[i].SVID[0].NotAfter)
		log.WithFields(logrus.Fields{
			telemetry.SPIFFEID: svid.X509Svid.Id.String(),
			telemetry.TTL:      ttl.Seconds(),
		}).Debug("Fetched X.509 SVID for delegated identity")
	}

	return nil
}

func composeX509SVIDBySelectors(update *cache.WorkloadUpdate) (*delegatedidentityv1.SubscribeToX509SVIDsResponse, error) {
	resp := new(delegatedidentityv1.SubscribeToX509SVIDsResponse)
	resp.X509Svids = []*delegatedidentityv1.X509SVIDWithKey{}

	for td := range update.FederatedBundles {
		resp.FederatesWith = append(resp.FederatesWith, td.IDString())
	}

	// Sort list to give a stable response instead of one dependent on the map
	// iteration order above.
	sort.Strings(resp.FederatesWith)

	for _, identity := range update.Identities {
		// Do not send admin nor downstream SVIDs to the caller
		if identity.Entry.Admin || identity.Entry.Downstream {
			continue
		}

		// check if SVIDs exist for the identity
		if len(identity.SVID) == 0 {
			return nil, fmt.Errorf("unable to get SVID from identity")
		}

		id, err := idutil.IDProtoFromString(identity.Entry.SpiffeId)
		if err != nil {
			return nil, fmt.Errorf("error during SPIFFE ID parsing: %w", err)
		}

		keyData, err := x509.MarshalPKCS8PrivateKey(identity.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("marshal key for %v: %w", id, err)
		}

		svid := &delegatedidentityv1.X509SVIDWithKey{
			X509Svid: &types.X509SVID{
				Id:        id,
				CertChain: x509util.RawCertsFromCertificates(identity.SVID),
				ExpiresAt: identity.SVID[0].NotAfter.Unix(),
				Hint:      identity.Entry.Hint,
			},
			X509SvidKey: keyData,
		}
		resp.X509Svids = append(resp.X509Svids, svid)
	}
	return resp, nil
}

func (s *Service) SubscribeToX509Bundles(_ *delegatedidentityv1.SubscribeToX509BundlesRequest, stream delegatedidentityv1.DelegatedIdentity_SubscribeToX509BundlesServer) error {
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)

	cachedSelectors, err := s.isCallerAuthorized(ctx, log, nil)
	if err != nil {
		return err
	}

	subscriber := s.manager.SubscribeToBundleChanges()

	// send initial update....
	caCerts := make(map[string][]byte)
	for td, bundle := range subscriber.Value() {
		caCerts[td.IDString()] = marshalBundle(bundle.X509Authorities())
	}

	resp := &delegatedidentityv1.SubscribeToX509BundlesResponse{
		CaCertificates: caCerts,
	}

	if err := stream.Send(resp); err != nil {
		return err
	}

	for {
		select {
		case <-subscriber.Changes():
			if _, err := s.isCallerAuthorized(ctx, log, cachedSelectors); err != nil {
				return err
			}

			for td, bundle := range subscriber.Next() {
				caCerts[td.IDString()] = marshalBundle(bundle.X509Authorities())
			}

			resp := &delegatedidentityv1.SubscribeToX509BundlesResponse{
				CaCertificates: caCerts,
			}

			if err := stream.Send(resp); err != nil {
				return err
			}

		case <-ctx.Done():
			return nil
		}
	}
}

func (s *Service) FetchJWTSVIDs(ctx context.Context, req *delegatedidentityv1.FetchJWTSVIDsRequest) (resp *delegatedidentityv1.FetchJWTSVIDsResponse, err error) {
	log := rpccontext.Logger(ctx)
	if len(req.Audience) == 0 {
		log.Error("Missing required audience parameter")
		return nil, status.Error(codes.InvalidArgument, "audience must be specified")
	}

	if _, err = s.isCallerAuthorized(ctx, log, nil); err != nil {
		return nil, err
	}

	selectors, err := api.SelectorsFromProto(req.Selectors)
	if err != nil {
		log.WithError(err).Error("Invalid argument; could not parse provided selectors")
		return nil, status.Error(codes.InvalidArgument, "could not parse provided selectors")
	}

	resp = new(delegatedidentityv1.FetchJWTSVIDsResponse)

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
		resp.Svids = append(resp.Svids, &types.JWTSVID{
			Token: svid.Token,
			Id: &types.SPIFFEID{
				TrustDomain: spiffeID.TrustDomain().Name(),
				Path:        spiffeID.Path(),
			},
			ExpiresAt: svid.ExpiresAt.Unix(),
			IssuedAt:  svid.IssuedAt.Unix(),
			Hint:      entry.Hint,
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

func (s *Service) SubscribeToJWTBundles(_ *delegatedidentityv1.SubscribeToJWTBundlesRequest, stream delegatedidentityv1.DelegatedIdentity_SubscribeToJWTBundlesServer) error {
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)

	cachedSelectors, err := s.isCallerAuthorized(ctx, log, nil)
	if err != nil {
		return err
	}

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

	resp := &delegatedidentityv1.SubscribeToJWTBundlesResponse{
		Bundles: jwtbundles,
	}

	if err := stream.Send(resp); err != nil {
		return err
	}
	for {
		select {
		case <-subscriber.Changes():
			if _, err := s.isCallerAuthorized(ctx, log, cachedSelectors); err != nil {
				return err
			}
			for td, bundle := range subscriber.Next() {
				jwksBytes, err := bundleutil.Marshal(bundle, bundleutil.NoX509SVIDKeys(), bundleutil.StandardJWKS())
				if err != nil {
					return err
				}
				jwtbundles[td.IDString()] = jwksBytes
			}

			resp := &delegatedidentityv1.SubscribeToJWTBundlesResponse{
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

func marshalBundle(certs []*x509.Certificate) []byte {
	bundle := []byte{}
	for _, c := range certs {
		bundle = append(bundle, c.Raw...)
	}
	return bundle
}
