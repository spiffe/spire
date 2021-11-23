package delegatedidentity

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/sirupsen/logrus"
	delegatedidentityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	workload_attestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/agent/endpoints"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/idutil"
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
	Manager             manager.Manager
	Attestor            workload_attestor.Attestor
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
		authorizedDelegates: AuthorizedDelegates,
	}
}

// Service implements the delegated identity server
type Service struct {
	delegatedidentityv1.UnsafeDelegatedIdentityServer

	manager  manager.Manager
	attestor attestor

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

	identities := s.manager.MatchingIdentities(callerSelectors)
	numRegisteredIDs := len(identities)

	if numRegisteredIDs == 0 {
		log.Error("no identity issued")
		return nil, status.Error(codes.PermissionDenied, "no identity issued")
	}

	for _, identity := range identities {
		if _, ok := s.authorizedDelegates[identity.Entry.SpiffeId]; ok {
			return callerSelectors, nil
		}
	}

	// caller has identity associeted with but none is authorized
	log.WithFields(logrus.Fields{
		"num_registered_ids": numRegisteredIDs,
		"default_id":         identities[0].Entry.SpiffeId,
	}).Error("Permission denied; caller not configured as an authorized delegate.")

	return nil, status.Error(codes.PermissionDenied, "caller not configured as an authorized delegate")
}

func (s *Service) SubscribeToX509SVIDs(req *delegatedidentityv1.SubscribeToX509SVIDsRequest, stream delegatedidentityv1.DelegatedIdentity_SubscribeToX509SVIDsServer) error {
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)
	cachedSelectors, err := s.isCallerAuthorized(ctx, log, nil)

	if err != nil {
		return err
	}

	selectors, err := api.SelectorsFromProto(req.Selectors)
	if err != nil {
		log.WithError(err).Error("Invalid argument; could not parse provided selectors")
		return status.Error(codes.InvalidArgument, "could not parse provided selectors")
	}

	subscriber := s.manager.SubscribeToCacheChanges(selectors)
	defer subscriber.Finish()

	for {
		select {
		case update := <-subscriber.Updates():
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

	return nil
}

func composeX509SVIDBySelectors(update *cache.WorkloadUpdate) (*delegatedidentityv1.SubscribeToX509SVIDsResponse, error) {
	resp := new(delegatedidentityv1.SubscribeToX509SVIDsResponse)
	resp.X509Svids = []*delegatedidentityv1.X509SVIDWithKey{}

	for td := range update.FederatedBundles {
		resp.FederatesWith = append(resp.FederatesWith, td.IDString())
	}

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
			},
			X509SvidKey: keyData,
		}
		resp.X509Svids = append(resp.X509Svids, svid)
	}
	return resp, nil
}

func (s *Service) SubscribeToX509Bundles(req *delegatedidentityv1.SubscribeToX509BundlesRequest, stream delegatedidentityv1.DelegatedIdentity_SubscribeToX509BundlesServer) error {
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
		caCerts[td.IDString()] = marshalBundle(bundle.RootCAs())
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
				caCerts[td.IDString()] = marshalBundle(bundle.RootCAs())
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

func marshalBundle(certs []*x509.Certificate) []byte {
	bundle := []byte{}
	for _, c := range certs {
		bundle = append(bundle, c.Raw...)
	}
	return bundle
}
