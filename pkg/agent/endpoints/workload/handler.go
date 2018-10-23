package workload

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/ptypes/struct"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/agent/auth"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/api/workload"
	"github.com/spiffe/spire/proto/common"
	"github.com/zeebo/errs"
	jose "gopkg.in/square/go-jose.v2"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	workloadApi = "workload_api"
	workloadPid = "workload_pid"
)

// Handler implements the Workload API interface
type Handler struct {
	Manager manager.Manager
	Catalog catalog.Catalog
	L       logrus.FieldLogger
	T       telemetry.Sink
}

func (h *Handler) FetchJWTASVID(ctx context.Context, req *workload.JWTASVIDRequest) (*workload.JWTASVIDResponse, error) {
	if len(req.Audience) == 0 {
		return nil, errs.New("audience cannot be empty")
	}

	_, selectors, _, done, err := h.startCall(ctx)
	if err != nil {
		return nil, err
	}
	defer done()

	// TODO: telemetry

	var spiffeIDs []string
	for _, entry := range h.Manager.MatchingEntries(selectors) {
		if req.SpiffeId != "" && entry.RegistrationEntry.SpiffeId != req.SpiffeId {
			continue
		}
		spiffeIDs = append(spiffeIDs, entry.RegistrationEntry.SpiffeId)
	}

	resp := new(workload.JWTASVIDResponse)
	for _, spiffeID := range spiffeIDs {
		svid, err := h.Manager.FetchJWTSVID(ctx, spiffeID, req.Audience)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "could not fetch %q JWTASVID: %v", spiffeID, err)
		}
		resp.Svids = append(resp.Svids, &workload.JWTASVID{
			SpiffeId: spiffeID,
			Svid:     svid,
		})
	}

	return resp, nil
}

func (h *Handler) FetchJWTABundles(req *workload.JWTABundlesRequest, stream workload.SpiffeWorkloadAPI_FetchJWTABundlesServer) error {
	ctx := stream.Context()

	pid, selectors, tel, done, err := h.startCall(ctx)
	if err != nil {
		return err
	}
	defer done()

	// TODO: telemetry

	subscriber := h.Manager.SubscribeToCacheChanges(selectors)
	defer subscriber.Finish()

	for {
		select {
		case update := <-subscriber.Updates():
			tel.IncrCounter([]string{workloadApi, "bundles_update"}, 1)
			start := time.Now()
			if err := h.sendJWTABundlesResponse(update, stream); err != nil {
				return err
			}

			tel.MeasureSince([]string{workloadApi, "send_jwt_bundle_latency"}, start)
			if time.Since(start) > (1 * time.Second) {
				h.L.Warnf("Took %v seconds to send JWT bundle to PID %v", time.Since(start).Seconds, pid)
			}
			return nil
		case <-ctx.Done():
			return nil
		}
	}

	return nil
}

func (h *Handler) ValidateJWTASVID(ctx context.Context, req *workload.ValidateJWTASVIDRequest) (*workload.ValidateJWTASVIDResponse, error) {
	_, selectors, tel, done, err := h.startCall(ctx)
	if err != nil {
		return nil, err
	}
	defer done()

	tel.IncrCounter([]string{workloadApi, "validate_jwt"}, 1)

	keyStore := keyStoreFromBundles(h.getWorkloadBundles(selectors))

	spiffeID, claims, err := jwtsvid.ValidateToken(ctx, req.Svid, keyStore, req.Audience)
	if err != nil {
		return nil, err
	}

	s, err := structFromValues(claims)
	if err != nil {
		return nil, err
	}

	return &workload.ValidateJWTASVIDResponse{
		SpiffeId: spiffeID,
		Claims:   s,
	}, nil

}

func (h *Handler) FetchX509SVID(_ *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	ctx := stream.Context()

	pid, selectors, tel, done, err := h.startCall(ctx)
	if err != nil {
		return err
	}
	defer done()

	subscriber := h.Manager.SubscribeToCacheChanges(selectors)
	defer subscriber.Finish()

	for {
		select {
		case update := <-subscriber.Updates():
			tel.IncrCounter([]string{workloadApi, "update"}, 1)

			start := time.Now()
			err := h.sendX509SVIDResponse(update, stream)
			if err != nil {
				return err
			}

			tel.MeasureSince([]string{workloadApi, "update_latency"}, start)
			if time.Since(start) > (1 * time.Second) {
				h.L.Warnf("Took %v seconds to send update to PID %v", time.Since(start).Seconds, pid)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (h *Handler) sendX509SVIDResponse(update *cache.WorkloadUpdate, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	if len(update.Entries) == 0 {
		return status.Errorf(codes.PermissionDenied, "no identity issued")
	}

	resp, err := h.composeX509SVIDResponse(update)
	if err != nil {
		return status.Errorf(codes.Unavailable, "could not serialize response: %v", err)
	}

	return stream.Send(resp)
}

func (h *Handler) composeX509SVIDResponse(update *cache.WorkloadUpdate) (*workload.X509SVIDResponse, error) {
	resp := new(workload.X509SVIDResponse)
	resp.Svids = []*workload.X509SVID{}
	resp.FederatedBundles = make(map[string][]byte)

	bundle := marshalBundle(update.Bundle.RootCAs())

	for id, federatedBundle := range update.FederatedBundles {
		resp.FederatedBundles[id] = marshalBundle(federatedBundle.RootCAs())
	}

	for _, e := range update.Entries {
		id := e.RegistrationEntry.SpiffeId

		keyData, err := x509.MarshalPKCS8PrivateKey(e.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("marshal key for %v: %v", id, err)
		}

		svid := &workload.X509SVID{
			SpiffeId:      id,
			X509Svid:      x509util.DERFromCertificates(e.SVID),
			X509SvidKey:   keyData,
			Bundle:        bundle,
			FederatesWith: e.RegistrationEntry.FederatesWith,
		}

		resp.Svids = append(resp.Svids, svid)
	}

	return resp, nil
}

func (h *Handler) sendJWTABundlesResponse(update *cache.WorkloadUpdate, stream workload.SpiffeWorkloadAPI_FetchJWTABundlesServer) error {
	if len(update.Entries) == 0 {
		return status.Errorf(codes.PermissionDenied, "no identity issued")
	}

	resp, err := h.composeJWTABundlesResponse(update)
	if err != nil {
		return status.Errorf(codes.Unavailable, "could not serialize response: %v", err)
	}

	return stream.Send(resp)
}

func (h *Handler) composeJWTABundlesResponse(update *cache.WorkloadUpdate) (*workload.JWTABundlesResponse, error) {
	resp := &workload.JWTABundlesResponse{
		Bundles: make(map[string][]byte),
	}

	jwksBytes, err := jwtJWKSBytesFromBundle(update.Bundle)
	if err != nil {
		return nil, err
	}
	resp.Bundles[update.Bundle.TrustDomainID()] = jwksBytes

	for _, federatedBundle := range update.FederatedBundles {
		jwksBytes, err := jwtJWKSBytesFromBundle(update.Bundle)
		if err != nil {
			return nil, err
		}
		resp.Bundles[federatedBundle.TrustDomainID()] = jwksBytes
	}

	return resp, nil
}

func (h *Handler) startCall(ctx context.Context) (int32, []*common.Selector, telemetry.Sink, func(), error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(md["workload.spiffe.io"]) != 1 || md["workload.spiffe.io"][0] != "true" {
		return 0, nil, nil, nil, status.Errorf(codes.InvalidArgument, "Security header missing from request")
	}

	pid, err := h.callerPID(ctx)
	if err != nil {
		return 0, nil, nil, nil, status.Errorf(codes.Internal, "Is this a supported system? Please report this bug: %v", err)
	}

	tel := telemetry.WithLabels(h.T, []telemetry.Label{{workloadPid, string(pid)}})
	tel.IncrCounter([]string{workloadApi, "connection"}, 1)
	tel.IncrCounter([]string{workloadApi, "connections"}, 1)

	config := attestor.Config{
		Catalog: h.Catalog,
		L:       h.L,
		T:       tel,
	}

	selectors := attestor.New(&config).Attest(ctx, pid)

	done := func() {
		defer tel.IncrCounter([]string{workloadApi, "connections"}, -1)
	}

	return pid, selectors, tel, done, nil
}

// callerPID takes a grpc context, and returns the PID of the caller which has issued
// the request. Returns an error if the call was not made locally, if the necessary
// syscalls aren't unsupported, or if the transport security was not properly configured.
// See the auth package for more information.
func (h *Handler) callerPID(ctx context.Context) (pid int32, err error) {
	info, ok := auth.CallerFromContext(ctx)
	if !ok {
		return 0, errors.New("Unable to fetch credentials from context")
	}

	if info.Err != nil {
		return 0, fmt.Errorf("Unable to resolve caller PID: %s", info.Err)
	}

	// If PID is 0, something is wrong...
	if info.PID == 0 {
		return 0, errors.New("Unable to resolve caller PID")
	}

	return info.PID, nil
}

func (h *Handler) getWorkloadBundles(selectors []*common.Selector) (bundles []*bundleutil.Bundle) {
	update := h.Manager.FetchWorkloadUpdate(selectors)

	bundles = append(bundles, update.Bundle)
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

func jwtJWKSBytesFromBundle(bundle *bundleutil.Bundle) ([]byte, error) {
	jwksBytes, err := json.Marshal(jwtJWKSFromBundle(bundle))
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return jwksBytes, nil
}

func jwtJWKSFromBundle(bundle *bundleutil.Bundle) *jose.JSONWebKeySet {
	jwks := new(jose.JSONWebKeySet)
	for keyID, jwtSigningKey := range bundle.JWTSigningKeys() {
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:   jwtSigningKey,
			KeyID: keyID,
			// TODO: fill in with proper use value when it is known
			Use: "JWT-SVID",
		})
	}
	return jwks
}
