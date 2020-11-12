package workload

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang/protobuf/jsonpb"
	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/api/rpccontext"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Manager interface {
	SubscribeToCacheChanges(cache.Selectors) cache.Subscriber
	MatchingIdentities([]*common.Selector) []cache.Identity
	FetchJWTSVID(ctx context.Context, spiffeID string, audience []string) (*client.JWTSVID, error)
	FetchWorkloadUpdate([]*common.Selector) *cache.WorkloadUpdate
}

type Attestor interface {
	Attest(ctx context.Context) ([]*common.Selector, error)
}

// Handler implements the Workload API interface
type Config struct {
	Manager  Manager
	Attestor Attestor
}

type Handler struct {
	c Config
}

func New(c Config) *Handler {
	return &Handler{
		c: c,
	}
}

// FetchJWTSVID processes request for a JWT-SVID
func (h *Handler) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (resp *workload.JWTSVIDResponse, err error) {
	log := rpccontext.Logger(ctx)
	if len(req.Audience) == 0 {
		log.Error("Missing required audience parameter")
		return nil, status.Error(codes.InvalidArgument, "audience must be specified")
	}

	selectors, err := h.c.Attestor.Attest(ctx)
	if err != nil {
		log.WithError(err).Error("Workload attestation failed")
		return nil, err
	}

	var spiffeIDs []string
	identities := h.c.Manager.MatchingIdentities(selectors)
	if len(identities) == 0 {
		log.WithField(telemetry.Registered, false).Error("No identity issued")
		return nil, status.Errorf(codes.PermissionDenied, "no identity issued")
	}

	log = log.WithField(telemetry.Registered, true)

	for _, identity := range identities {
		if req.SpiffeId != "" && identity.Entry.SpiffeId != req.SpiffeId {
			continue
		}
		spiffeIDs = append(spiffeIDs, identity.Entry.SpiffeId)
	}

	resp = new(workload.JWTSVIDResponse)
	for _, spiffeID := range spiffeIDs {
		loopLog := log.WithField(telemetry.SPIFFEID, spiffeID)

		var svid *client.JWTSVID
		svid, err = h.c.Manager.FetchJWTSVID(ctx, spiffeID, req.Audience)
		if err != nil {
			log.WithError(err).Error("Could not fetch JWT-SVID")
			return nil, status.Errorf(codes.Unavailable, "could not fetch JWT-SVID: %v", err)
		}
		resp.Svids = append(resp.Svids, &workload.JWTSVID{
			SpiffeId: spiffeID,
			Svid:     svid.Token,
		})

		ttl := time.Until(svid.ExpiresAt)
		loopLog.WithField(telemetry.TTL, ttl.Seconds()).Debug("Fetched JWT SVID")
	}

	return resp, nil
}

// FetchJWTBundles processes request for JWT bundles
func (h *Handler) FetchJWTBundles(req *workload.JWTBundlesRequest, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)

	selectors, err := h.c.Attestor.Attest(ctx)
	if err != nil {
		log.WithError(err).Error("Workload attestation failed")
		return err
	}

	subscriber := h.c.Manager.SubscribeToCacheChanges(selectors)
	defer subscriber.Finish()

	for {
		select {
		case update := <-subscriber.Updates():
			if err := sendJWTBundlesResponse(update, stream, log); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// ValidateJWTSVID processes request for JWT-SVID validation
func (h *Handler) ValidateJWTSVID(ctx context.Context, req *workload.ValidateJWTSVIDRequest) (*workload.ValidateJWTSVIDResponse, error) {
	log := rpccontext.Logger(ctx)
	if req.Audience == "" {
		log.Error("Missing required audience parameter")
		return nil, status.Error(codes.InvalidArgument, "audience must be specified")
	}
	if req.Svid == "" {
		log.Error("Missing required svid parameter")
		return nil, status.Error(codes.InvalidArgument, "svid must be specified")
	}

	log = log.WithField(telemetry.Audience, req.Audience)

	selectors, err := h.c.Attestor.Attest(ctx)
	if err != nil {
		log.WithError(err).Error("Workload attestation failed")
		return nil, err
	}

	keyStore := keyStoreFromBundles(h.getWorkloadBundles(selectors))

	spiffeID, claims, err := jwtsvid.ValidateToken(ctx, req.Svid, keyStore, []string{req.Audience})
	if err != nil {
		log.WithError(err).Warn("Failed to validate JWT")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	log.WithField(telemetry.SPIFFEID, spiffeID).Debug("Successfully validated JWT")

	s, err := structFromValues(claims)
	if err != nil {
		log.WithError(err).Error("Error deserializing claims from JWT-SVID")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	return &workload.ValidateJWTSVIDResponse{
		SpiffeId: spiffeID,
		Claims:   s,
	}, nil
}

// FetchX509SVID processes request for an x509 SVID
func (h *Handler) FetchX509SVID(_ *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)

	selectors, err := h.c.Attestor.Attest(ctx)
	if err != nil {
		log.WithError(err).Error("Workload attestation failed")
		return err
	}

	subscriber := h.c.Manager.SubscribeToCacheChanges(selectors)
	defer subscriber.Finish()

	for {
		select {
		case update := <-subscriber.Updates():
			if err := sendX509SVIDResponse(update, stream, log); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func sendX509SVIDResponse(update *cache.WorkloadUpdate, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer, log logrus.FieldLogger) (err error) {
	if len(update.Identities) == 0 {
		log.WithField(telemetry.Registered, false).Error("No identity issued")
		return status.Error(codes.PermissionDenied, "no identity issued")
	}

	log = log.WithField(telemetry.Registered, true)

	resp, err := composeX509SVIDResponse(update)
	if err != nil {
		log.WithError(err).Error("Could not serialize X.509 SVID response")
		return status.Errorf(codes.Unavailable, "could not serialize response: %v", err)
	}

	if err := stream.Send(resp); err != nil {
		log.WithError(err).Error("Failed to send X.509 SVID response")
		return err
	}

	log = log.WithField(telemetry.Count, len(resp.Svids))

	// log and emit telemetry on each SVID
	// a response has already been sent so nothing is
	// blocked on this logic
	for i, svid := range resp.Svids {
		ttl := time.Until(update.Identities[i].SVID[0].NotAfter)
		log.WithFields(logrus.Fields{
			telemetry.SPIFFEID: svid.SpiffeId,
			telemetry.TTL:      ttl.Seconds(),
		}).Debug("Fetched X.509 SVID")
	}

	return nil
}

func composeX509SVIDResponse(update *cache.WorkloadUpdate) (*workload.X509SVIDResponse, error) {
	resp := new(workload.X509SVIDResponse)
	resp.Svids = []*workload.X509SVID{}
	resp.FederatedBundles = make(map[string][]byte)

	bundle := marshalBundle(update.Bundle.RootCAs())

	for id, federatedBundle := range update.FederatedBundles {
		resp.FederatedBundles[id] = marshalBundle(federatedBundle.RootCAs())
	}

	for _, identity := range update.Identities {
		id := identity.Entry.SpiffeId

		keyData, err := x509.MarshalPKCS8PrivateKey(identity.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("marshal key for %v: %v", id, err)
		}

		svid := &workload.X509SVID{
			SpiffeId:    id,
			X509Svid:    x509util.DERFromCertificates(identity.SVID),
			X509SvidKey: keyData,
			Bundle:      bundle,
		}

		resp.Svids = append(resp.Svids, svid)
	}

	return resp, nil
}

func sendJWTBundlesResponse(update *cache.WorkloadUpdate, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer, log logrus.FieldLogger) (err error) {
	if len(update.Identities) == 0 {
		log.WithField(telemetry.Registered, false).Error("No identity issued")
		return status.Errorf(codes.PermissionDenied, "no identity issued")
	}

	resp, err := composeJWTBundlesResponse(update)
	if err != nil {
		log.WithError(err).Error("Could not serialize JWT bundle response")
		return status.Errorf(codes.Unavailable, "could not serialize response: %v", err)
	}

	if err := stream.Send(resp); err != nil {
		log.WithError(err).Error("Failed to send JWT bundle response")
		return err
	}

	return nil
}

func composeJWTBundlesResponse(update *cache.WorkloadUpdate) (*workload.JWTBundlesResponse, error) {
	bundles := make(map[string][]byte)
	if update.Bundle != nil {
		jwksBytes, err := bundleutil.Marshal(update.Bundle, bundleutil.NoX509SVIDKeys(), bundleutil.StandardJWKS())
		if err != nil {
			return nil, err
		}
		bundles[update.Bundle.TrustDomainID()] = jwksBytes
	}

	for _, federatedBundle := range update.FederatedBundles {
		jwksBytes, err := bundleutil.Marshal(federatedBundle, bundleutil.NoX509SVIDKeys(), bundleutil.StandardJWKS())
		if err != nil {
			return nil, err
		}
		bundles[federatedBundle.TrustDomainID()] = jwksBytes
	}

	return &workload.JWTBundlesResponse{
		Bundles: bundles,
	}, nil
}

func (h *Handler) getWorkloadBundles(selectors []*common.Selector) (bundles []*bundleutil.Bundle) {
	update := h.c.Manager.FetchWorkloadUpdate(selectors)

	if update.Bundle != nil {
		bundles = append(bundles, update.Bundle)
	}
	for _, federatedBundle := range update.FederatedBundles {
		bundles = append(bundles, federatedBundle)
	}
	return bundles
}

func marshalBundle(certs []*x509.Certificate) []byte {
	bundle := []byte{}
	for _, c := range certs {
		bundle = append(bundle, c.Raw...)
	}
	return bundle
}

func keyStoreFromBundles(bundles []*bundleutil.Bundle) jwtsvid.KeyStore {
	trustDomainKeys := make(map[string]map[string]crypto.PublicKey)
	for _, bundle := range bundles {
		trustDomainKeys[bundle.TrustDomainID()] = bundle.JWTSigningKeys()
	}
	return jwtsvid.NewKeyStore(trustDomainKeys)
}

func structFromValues(values map[string]interface{}) (*structpb.Struct, error) {
	valuesJSON, err := json.Marshal(values)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	s := new(structpb.Struct)
	if err := jsonpb.Unmarshal(bytes.NewReader(valuesJSON), s); err != nil {
		return nil, errs.Wrap(err)
	}

	return s, nil
}
