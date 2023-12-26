package workload

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

type Manager interface {
	SubscribeToCacheChanges(ctx context.Context, key cache.Selectors) (cache.Subscriber, error)
	MatchingRegistrationEntries(selectors []*common.Selector) []*common.RegistrationEntry
	FetchJWTSVID(ctx context.Context, entry *common.RegistrationEntry, audience []string) (*client.JWTSVID, error)
	FetchWorkloadUpdate([]*common.Selector) *cache.WorkloadUpdate
}

type Attestor interface {
	Attest(ctx context.Context) ([]*common.Selector, error)
}

type Config struct {
	Manager                       Manager
	Attestor                      Attestor
	AllowUnauthenticatedVerifiers bool
	AllowedForeignJWTClaims       map[string]struct{}
	TrustDomain                   spiffeid.TrustDomain
}

// Handler implements the Workload API interface
type Handler struct {
	workload.UnsafeSpiffeWorkloadAPIServer
	c Config
}

func New(c Config) *Handler {
	return &Handler{
		c: c,
	}
}

// FetchJWTSVID processes request for a JWT-SVID. In case of multiple fetched SVIDs with same hint, the SVID that has the oldest
// associated entry will be returned.
func (h *Handler) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (resp *workload.JWTSVIDResponse, err error) {
	log := rpccontext.Logger(ctx)
	if len(req.Audience) == 0 {
		log.Error("Missing required audience parameter")
		return nil, status.Error(codes.InvalidArgument, "audience must be specified")
	}

	if req.SpiffeId != "" {
		if _, err := spiffeid.FromString(req.SpiffeId); err != nil {
			log.WithField(telemetry.SPIFFEID, req.SpiffeId).WithError(err).Error("Invalid requested SPIFFE ID")
			return nil, status.Errorf(codes.InvalidArgument, "invalid requested SPIFFE ID: %v", err)
		}
	}

	selectors, err := h.c.Attestor.Attest(ctx)
	if err != nil {
		log.WithError(err).Error("Workload attestation failed")
		return nil, err
	}

	log = log.WithField(telemetry.Registered, true)

	entries := h.c.Manager.MatchingRegistrationEntries(selectors)
	entries = filterRegistrations(entries, log)

	resp = new(workload.JWTSVIDResponse)

	for _, entry := range entries {
		if req.SpiffeId != "" && entry.SpiffeId != req.SpiffeId {
			continue
		}
		loopLog := log.WithField(telemetry.SPIFFEID, entry.SpiffeId)
		svid, err := h.fetchJWTSVID(ctx, loopLog, entry, req.Audience)
		if err != nil {
			return nil, err
		}

		resp.Svids = append(resp.Svids, svid)
	}

	if len(resp.Svids) == 0 {
		log.WithField(telemetry.Registered, false).Error("No identity issued")
		return nil, status.Error(codes.PermissionDenied, "no identity issued")
	}

	return resp, nil
}

// FetchJWTBundles processes request for JWT bundles
func (h *Handler) FetchJWTBundles(_ *workload.JWTBundlesRequest, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)

	selectors, err := h.c.Attestor.Attest(ctx)
	if err != nil {
		log.WithError(err).Error("Workload attestation failed")
		return err
	}

	subscriber, err := h.c.Manager.SubscribeToCacheChanges(ctx, selectors)
	if err != nil {
		log.WithError(err).Error("Subscribe to cache changes failed")
		return err
	}
	defer subscriber.Finish()

	var previousResp *workload.JWTBundlesResponse
	for {
		select {
		case update := <-subscriber.Updates():
			if previousResp, err = sendJWTBundlesResponse(update, stream, log, h.c.AllowUnauthenticatedVerifiers, previousResp); err != nil {
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

	bundles := h.getWorkloadBundles(selectors)

	keyStore, err := keyStoreFromBundles(bundles)
	if err != nil {
		log.WithError(err).Error("Failed to build key store from bundles")
		return nil, status.Error(codes.Internal, err.Error())
	}

	id, claims, err := jwtsvid.ValidateToken(ctx, req.Svid, keyStore, []string{req.Audience})
	if err != nil {
		log.WithError(err).Warn("Failed to validate JWT")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	log.WithField(telemetry.SPIFFEID, id).Debug("Successfully validated JWT")

	if !id.MemberOf(h.c.TrustDomain) {
		for claim := range claims {
			if !isClaimAllowed(claim, h.c.AllowedForeignJWTClaims) {
				delete(claims, claim)
			}
		}
	}

	// RFC 7519 structures `aud` as an array of StringOrURIs but has a special
	// case where it MAY be specified as a single StringOrURI if there is only
	// one audience. We have traditionally always returned it as an array but
	// the JWT library we use now returns a single string when there is only
	// one. To maintain backcompat, convert a single string value for the
	// audience to a list.
	if aud, ok := claims["aud"].(string); ok {
		claims["aud"] = []string{aud}
	}

	s, err := structFromValues(claims)
	if err != nil {
		log.WithError(err).Error("Error deserializing claims from JWT-SVID")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	return &workload.ValidateJWTSVIDResponse{
		SpiffeId: id.String(),
		Claims:   s,
	}, nil
}

// FetchX509SVID processes request for a x509 SVID. In case of multiple fetched SVIDs with same hint, the SVID that has the oldest
// associated entry will be returned.
func (h *Handler) FetchX509SVID(_ *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)

	selectors, err := h.c.Attestor.Attest(ctx)
	if err != nil {
		log.WithError(err).Error("Workload attestation failed")
		return err
	}

	subscriber, err := h.c.Manager.SubscribeToCacheChanges(ctx, selectors)
	if err != nil {
		log.WithError(err).Error("Subscribe to cache changes failed")
		return err
	}
	defer subscriber.Finish()

	// The agent health check currently exercises the Workload API.
	// Only log if it is not the agent itself.
	quietLogging := isAgent(ctx)
	for {
		select {
		case update := <-subscriber.Updates():
			update.Identities = filterIdentities(update.Identities, log)
			if err := sendX509SVIDResponse(update, stream, log, quietLogging); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// FetchX509Bundles processes request for x509 bundles
func (h *Handler) FetchX509Bundles(_ *workload.X509BundlesRequest, stream workload.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)

	selectors, err := h.c.Attestor.Attest(ctx)
	if err != nil {
		log.WithError(err).Error("Workload attestation failed")
		return err
	}

	subscriber, err := h.c.Manager.SubscribeToCacheChanges(ctx, selectors)
	if err != nil {
		log.WithError(err).Error("Subscribe to cache changes failed")
		return err
	}
	defer subscriber.Finish()

	// The agent health check currently exercises the Workload API.
	// Only log if it is not the agent itself.
	quietLogging := isAgent(ctx)
	var previousResp *workload.X509BundlesResponse
	for {
		select {
		case update := <-subscriber.Updates():
			previousResp, err = sendX509BundlesResponse(update, stream, log, h.c.AllowUnauthenticatedVerifiers, previousResp, quietLogging)
			if err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (h *Handler) fetchJWTSVID(ctx context.Context, log logrus.FieldLogger, entry *common.RegistrationEntry, audience []string) (*workload.JWTSVID, error) {
	spiffeID, err := spiffeid.FromString(entry.SpiffeId)
	if err != nil {
		log.WithError(err).Error("Invalid requested SPIFFE ID")
		return nil, status.Errorf(codes.InvalidArgument, "invalid requested SPIFFE ID: %v", err)
	}

	svid, err := h.c.Manager.FetchJWTSVID(ctx, entry, audience)
	if err != nil {
		log.WithError(err).Error("Could not fetch JWT-SVID")
		return nil, status.Errorf(codes.Unavailable, "could not fetch JWT-SVID: %v", err)
	}

	ttl := time.Until(svid.ExpiresAt)
	log.WithField(telemetry.TTL, ttl.Seconds()).Debug("Fetched JWT SVID")

	return &workload.JWTSVID{
		SpiffeId: spiffeID.String(),
		Svid:     svid.Token,
		Hint:     entry.Hint,
	}, nil
}

func sendX509BundlesResponse(update *cache.WorkloadUpdate, stream workload.SpiffeWorkloadAPI_FetchX509BundlesServer, log logrus.FieldLogger, allowUnauthenticatedVerifiers bool, previousResponse *workload.X509BundlesResponse, quietLogging bool) (*workload.X509BundlesResponse, error) {
	if !allowUnauthenticatedVerifiers && !update.HasIdentity() {
		if !quietLogging {
			log.WithField(telemetry.Registered, false).Error("No identity issued")
		}
		return nil, status.Error(codes.PermissionDenied, "no identity issued")
	}

	resp, err := composeX509BundlesResponse(update)
	if err != nil {
		log.WithError(err).Error("Could not serialize X509 bundle response")
		return nil, status.Errorf(codes.Unavailable, "could not serialize response: %v", err)
	}

	if proto.Equal(resp, previousResponse) {
		return previousResponse, nil
	}

	if err := stream.Send(resp); err != nil {
		log.WithError(err).Error("Failed to send X509 bundle response")
		return nil, err
	}

	return resp, nil
}

func composeX509BundlesResponse(update *cache.WorkloadUpdate) (*workload.X509BundlesResponse, error) {
	if update.Bundle == nil {
		// This should be purely defensive since the cache should always supply
		// a bundle.
		return nil, errors.New("bundle not available")
	}

	bundles := make(map[string][]byte)
	bundles[update.Bundle.TrustDomain().IDString()] = marshalBundle(update.Bundle.X509Authorities())
	if update.HasIdentity() {
		for _, federatedBundle := range update.FederatedBundles {
			bundles[federatedBundle.TrustDomain().IDString()] = marshalBundle(federatedBundle.X509Authorities())
		}
	}

	return &workload.X509BundlesResponse{
		Bundles: bundles,
	}, nil
}

func sendX509SVIDResponse(update *cache.WorkloadUpdate, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer, log logrus.FieldLogger, quietLogging bool) (err error) {
	if len(update.Identities) == 0 {
		if !quietLogging {
			log.WithField(telemetry.Registered, false).Error("No identity issued")
		}
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
	if !quietLogging {
		for i, svid := range resp.Svids {
			ttl := time.Until(update.Identities[i].SVID[0].NotAfter)
			log.WithFields(logrus.Fields{
				telemetry.SPIFFEID: svid.SpiffeId,
				telemetry.TTL:      ttl.Seconds(),
			}).Debug("Fetched X.509 SVID")
		}
	}

	return nil
}

func composeX509SVIDResponse(update *cache.WorkloadUpdate) (*workload.X509SVIDResponse, error) {
	resp := new(workload.X509SVIDResponse)
	resp.Svids = []*workload.X509SVID{}
	resp.FederatedBundles = make(map[string][]byte)

	bundle := marshalBundle(update.Bundle.X509Authorities())

	for td, federatedBundle := range update.FederatedBundles {
		resp.FederatedBundles[td.IDString()] = marshalBundle(federatedBundle.X509Authorities())
	}

	for _, identity := range update.Identities {
		id := identity.Entry.SpiffeId

		keyData, err := x509.MarshalPKCS8PrivateKey(identity.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("marshal key for %v: %w", id, err)
		}

		svid := &workload.X509SVID{
			SpiffeId:    id,
			X509Svid:    x509util.DERFromCertificates(identity.SVID),
			X509SvidKey: keyData,
			Bundle:      bundle,
			Hint:        identity.Entry.Hint,
		}

		resp.Svids = append(resp.Svids, svid)
	}

	return resp, nil
}

func sendJWTBundlesResponse(update *cache.WorkloadUpdate, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer, log logrus.FieldLogger, allowUnauthenticatedVerifiers bool, previousResponse *workload.JWTBundlesResponse) (*workload.JWTBundlesResponse, error) {
	if !allowUnauthenticatedVerifiers && !update.HasIdentity() {
		log.WithField(telemetry.Registered, false).Error("No identity issued")
		return nil, status.Error(codes.PermissionDenied, "no identity issued")
	}

	resp, err := composeJWTBundlesResponse(update)
	if err != nil {
		log.WithError(err).Error("Could not serialize JWT bundle response")
		return nil, status.Errorf(codes.Unavailable, "could not serialize response: %v", err)
	}

	if proto.Equal(resp, previousResponse) {
		return previousResponse, nil
	}

	if err := stream.Send(resp); err != nil {
		log.WithError(err).Error("Failed to send JWT bundle response")
		return nil, err
	}

	return resp, nil
}

func composeJWTBundlesResponse(update *cache.WorkloadUpdate) (*workload.JWTBundlesResponse, error) {
	if update.Bundle == nil {
		// This should be purely defensive since the cache should always supply
		// a bundle.
		return nil, errors.New("bundle not available")
	}

	bundles := make(map[string][]byte)
	jwksBytes, err := bundleutil.Marshal(update.Bundle, bundleutil.NoX509SVIDKeys(), bundleutil.StandardJWKS())
	if err != nil {
		return nil, err
	}
	bundles[update.Bundle.TrustDomain().IDString()] = jwksBytes

	if update.HasIdentity() {
		for _, federatedBundle := range update.FederatedBundles {
			jwksBytes, err := bundleutil.Marshal(federatedBundle, bundleutil.NoX509SVIDKeys(), bundleutil.StandardJWKS())
			if err != nil {
				return nil, err
			}
			bundles[federatedBundle.TrustDomain().IDString()] = jwksBytes
		}
	}

	return &workload.JWTBundlesResponse{
		Bundles: bundles,
	}, nil
}

// isAgent returns true if the caller PID from the provided context is the
// agent's process ID.
func isAgent(ctx context.Context) bool {
	return rpccontext.CallerPID(ctx) == os.Getpid()
}

func (h *Handler) getWorkloadBundles(selectors []*common.Selector) (bundles []*spiffebundle.Bundle) {
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

func keyStoreFromBundles(bundles []*spiffebundle.Bundle) (jwtsvid.KeyStore, error) {
	trustDomainKeys := make(map[spiffeid.TrustDomain]map[string]crypto.PublicKey)
	for _, bundle := range bundles {
		td, err := spiffeid.TrustDomainFromString(bundle.TrustDomain().IDString())
		if err != nil {
			return nil, err
		}
		trustDomainKeys[td] = bundle.JWTAuthorities()
	}
	return jwtsvid.NewKeyStore(trustDomainKeys), nil
}

func structFromValues(values map[string]any) (*structpb.Struct, error) {
	valuesJSON, err := json.Marshal(values)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	s := new(structpb.Struct)
	if err := protojson.Unmarshal(valuesJSON, s); err != nil {
		return nil, errs.Wrap(err)
	}

	return s, nil
}

func isClaimAllowed(claim string, allowedClaims map[string]struct{}) bool {
	switch claim {
	case "sub", "exp", "aud":
		return true
	default:
		_, ok := allowedClaims[claim]
		return ok
	}
}

func filterIdentities(identities []cache.Identity, log logrus.FieldLogger) []cache.Identity {
	var filteredIdentities []cache.Identity
	var entries []*common.RegistrationEntry
	for _, identity := range identities {
		entries = append(entries, identity.Entry)
	}

	entriesToRemove := getEntriesToRemove(entries, log)

	for _, identity := range identities {
		if _, ok := entriesToRemove[identity.Entry.EntryId]; !ok {
			filteredIdentities = append(filteredIdentities, identity)
		}
	}

	return filteredIdentities
}

func filterRegistrations(entries []*common.RegistrationEntry, log logrus.FieldLogger) []*common.RegistrationEntry {
	var filteredEntries []*common.RegistrationEntry
	entriesToRemove := getEntriesToRemove(entries, log)

	for _, entry := range entries {
		if _, ok := entriesToRemove[entry.EntryId]; !ok {
			filteredEntries = append(filteredEntries, entry)
		}
	}

	return filteredEntries
}

func getEntriesToRemove(entries []*common.RegistrationEntry, log logrus.FieldLogger) map[string]struct{} {
	entriesToRemove := make(map[string]struct{})
	hintsMap := make(map[string]*common.RegistrationEntry)

	for _, entry := range entries {
		if entry.Hint == "" {
			continue
		}
		if entryWithNonUniqueHint, ok := hintsMap[entry.Hint]; ok {
			entryToMaintain, entryToRemove := hintTieBreaking(entry, entryWithNonUniqueHint)

			hintsMap[entry.Hint] = entryToMaintain
			entriesToRemove[entryToRemove.EntryId] = struct{}{}

			log.WithFields(logrus.Fields{
				telemetry.Hint:           entryToRemove.Hint,
				telemetry.RegistrationID: entryToRemove.EntryId,
			}).Warn("Ignoring entry with duplicate hint")
		} else {
			hintsMap[entry.Hint] = entry
		}
	}

	return entriesToRemove
}

func hintTieBreaking(entryA *common.RegistrationEntry, entryB *common.RegistrationEntry) (maintain *common.RegistrationEntry, remove *common.RegistrationEntry) {
	switch {
	case entryA.CreatedAt < entryB.CreatedAt:
		maintain = entryA
		remove = entryB
	case entryA.CreatedAt > entryB.CreatedAt:
		maintain = entryB
		remove = entryA
	default:
		if entryA.EntryId < entryB.EntryId {
			maintain = entryA
			remove = entryB
		} else {
			maintain = entryB
			remove = entryA
		}
	}
	return
}
