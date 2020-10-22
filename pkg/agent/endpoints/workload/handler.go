package workload

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/golang/protobuf/jsonpb"
	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	attestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_workload "github.com/spiffe/spire/pkg/common/telemetry/agent/workloadapi"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Handler implements the Workload API interface
type Handler struct {
	Manager manager.Manager
	Catalog catalog.Catalog
	Log     logrus.FieldLogger
	Metrics telemetry.Metrics

	// tracks the number of outstanding connections
	connections int32
}

// FetchJWTSVID processes request for a JWT-SVID
func (h *Handler) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (resp *workload.JWTSVIDResponse, err error) {
	log := h.Log.WithField(telemetry.Method, telemetry.FetchJWTSVID)
	if len(req.Audience) == 0 {
		return nil, errs.New("audience must be specified")
	}

	_, selectors, metrics, done, err := h.startCall(ctx)
	if err != nil {
		return nil, err
	}
	defer done()

	counter := telemetry_workload.StartFetchJWTSVIDCall(metrics)
	defer counter.Done(&err)

	var spiffeIDs []string
	identities := h.Manager.MatchingIdentities(selectors)
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

	log = log.WithField(telemetry.Count, len(spiffeIDs))

	resp = new(workload.JWTSVIDResponse)
	for _, spiffeID := range spiffeIDs {
		loopLog := log.WithField(telemetry.SPIFFEID, spiffeID)

		var svid *client.JWTSVID
		svid, err = h.Manager.FetchJWTSVID(ctx, spiffeID, req.Audience)
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
	log := h.Log.WithField(telemetry.Method, telemetry.FetchJWTBundles)
	ctx := stream.Context()

	pid, selectors, metrics, done, err := h.startCall(ctx)
	if err != nil {
		log.WithError(err).Error("Failed to fetch JWT Bundles during context parsing")
		return err
	}
	defer done()

	telemetry_workload.IncrFetchJWTBundlesCounter(metrics)
	log = log.WithField(telemetry.PID, pid)
	log.Debug("Fetching JWT Bundles")

	subscriber := h.Manager.SubscribeToCacheChanges(selectors)
	defer subscriber.Finish()

	for {
		select {
		case update := <-subscriber.Updates():
			telemetry_workload.IncrUpdateJWTBundlesCounter(metrics)
			log.Debug("Sending JWT Bundles")
			start := time.Now()
			if err := h.sendJWTBundlesResponse(update, stream, metrics); err != nil {
				log.WithError(err).Error("Failed to send response")
				return err
			}

			telemetry_workload.MeasureSendJWTBundleLatency(metrics, start)
			if time.Since(start) > (1 * time.Second) {
				log.WithField(telemetry.Seconds, time.Since(start).Seconds).Warn("Took >1 second to send JWT bundle to PID")
			} else {
				log.Debug("Sent JWT bundle to PID")
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// ValidateJWTSVID processes request for JWT-SVID validation
func (h *Handler) ValidateJWTSVID(ctx context.Context, req *workload.ValidateJWTSVIDRequest) (*workload.ValidateJWTSVIDResponse, error) {
	log := h.Log.WithField(telemetry.Method, telemetry.ValidateJWTSVID)
	if req.Audience == "" {
		log.Error("Missing required audience parameter")
		return nil, status.Error(codes.InvalidArgument, "audience must be specified")
	}

	log = log.WithField(telemetry.Audience, req.Audience)
	if req.Svid == "" {
		log.Error("Missing required svid parameter")
		return nil, status.Error(codes.InvalidArgument, "svid must be specified")
	}

	_, selectors, metrics, done, err := h.startCall(ctx)
	if err != nil {
		log.WithError(err).Error("Failed to validate JWT-SVID during context parsing")
		return nil, err
	}
	defer done()

	keyStore := keyStoreFromBundles(h.getWorkloadBundles(selectors))

	spiffeID, claims, err := jwtsvid.ValidateToken(ctx, req.Svid, keyStore, []string{req.Audience})
	if err != nil {
		telemetry_workload.IncrValidJWTSVIDErrCounter(metrics)
		log.WithFields(logrus.Fields{
			telemetry.Error: err.Error(),
			telemetry.SVID:  req.Svid,
		}).Warn("Failed to validate JWT")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	telemetry_workload.IncrValidJWTSVIDCounter(metrics, spiffeID, req.Audience)
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

	pid, selectors, metrics, done, err := h.startCall(ctx)
	if err != nil {
		return err
	}
	defer done()

	subscriber := h.Manager.SubscribeToCacheChanges(selectors)
	defer subscriber.Finish()

	for {
		select {
		case update := <-subscriber.Updates():
			start := time.Now()
			err := h.sendX509SVIDResponse(update, stream, metrics)
			if err != nil {
				return err
			}

			// TODO: evaluate the possibility of removing the following metric at some point
			// in the future because almost the same metric (with different labels and keys) is being
			// taken by the CallCounter in sendX509SVIDResponse function.
			telemetry_workload.MeasureFetchX509SVIDLatency(metrics, start)
			if time.Since(start) > (1 * time.Second) {
				h.Log.WithFields(logrus.Fields{
					telemetry.Seconds: time.Since(start).Seconds,
					telemetry.PID:     pid,
				}).Warn("Took >1 second to send SVID response to PID")
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (h *Handler) sendX509SVIDResponse(update *cache.WorkloadUpdate, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer, metrics telemetry.Metrics) (err error) {
	counter := telemetry_workload.StartFetchX509SVIDCall(metrics)
	defer counter.Done(&err)

	log := h.Log

	if len(update.Identities) == 0 {
		log.WithField(telemetry.Registered, false).WithError(err).Error("No identity issued")
		return status.Error(codes.PermissionDenied, "no identity issued")
	}

	log = log.WithField(telemetry.Registered, true)

	resp, err := h.composeX509SVIDResponse(update)
	if err != nil {
		log.WithError(err).Error("Could not serialize X.509 SVID response")
		return status.Errorf(codes.Unavailable, "could not serialize response: %v", err)
	}

	err = stream.Send(resp)
	if err != nil {
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

func (h *Handler) composeX509SVIDResponse(update *cache.WorkloadUpdate) (*workload.X509SVIDResponse, error) {
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

func (h *Handler) sendJWTBundlesResponse(update *cache.WorkloadUpdate, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer, metrics telemetry.Metrics) (err error) {
	counter := telemetry_workload.StartFetchJWTBundlesCall(metrics)
	defer counter.Done(&err)

	if len(update.Identities) == 0 {
		return status.Errorf(codes.PermissionDenied, "no identity issued")
	}

	resp, err := h.composeJWTBundlesResponse(update)
	if err != nil {
		return status.Errorf(codes.Unavailable, "could not serialize response: %v", err)
	}

	return stream.Send(resp)
}

func (h *Handler) composeJWTBundlesResponse(update *cache.WorkloadUpdate) (*workload.JWTBundlesResponse, error) {
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

// From context, parse out peer watcher PID and selectors. Attest against the PID. Add selectors as labels to
// to a new metrics object. Return this information to the caller so it can emit further metrics.
// If no error, callers must call the output func() to decrement current connections count.
func (h *Handler) startCall(ctx context.Context) (int32, []*common.Selector, telemetry.Metrics, func(), error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(md["workload.spiffe.io"]) != 1 || md["workload.spiffe.io"][0] != "true" {
		return 0, nil, nil, nil, status.Errorf(codes.InvalidArgument, "Security header missing from request")
	}

	watcher, err := h.peerWatcher(ctx)
	if err != nil {
		return 0, nil, nil, nil, status.Errorf(codes.Internal, "Is this a supported system? Please report this bug: %v", err)
	}

	// add to count of current
	telemetry_workload.SetConnectionTotalGauge(h.Metrics, atomic.AddInt32(&h.connections, 1))
	h.Log.Debug("New active connection to workload API")
	done := func() {
		// rely on caller to decrement count of current connections
		telemetry_workload.SetConnectionTotalGauge(h.Metrics, atomic.AddInt32(&h.connections, -1))
		h.Log.Debug("Closing connection to workload API")
	}

	config := attestor.Config{
		Catalog: h.Catalog,
		Log:     h.Log,
		Metrics: h.Metrics,
	}

	selectors := attestor.New(&config).Attest(ctx, watcher.PID())

	// Ensure that the original caller is still alive so that we know we didn't
	// attest some other process that happened to be assigned the original PID
	if err := watcher.IsAlive(); err != nil {
		done()
		return 0, nil, nil, nil, status.Errorf(codes.Unauthenticated, "Could not verify existence of the original caller: %v", err)
	}

	telemetry_workload.IncrConnectionCounter(h.Metrics)

	return watcher.PID(), selectors, h.Metrics, done, nil
}

// peerWatcher takes a grpc context, and returns a Watcher representing the caller which
// has issued the request. Returns an error if the call was not made locally, if the necessary
// syscalls aren't unsupported, or if the transport security was not properly configured.
// See the peertracker package for more information.
func (h *Handler) peerWatcher(ctx context.Context) (watcher peertracker.Watcher, err error) {
	watcher, ok := peertracker.WatcherFromContext(ctx)
	if !ok {
		return nil, errors.New("unable to fetch watcher from context")
	}

	return watcher, nil
}

func (h *Handler) getWorkloadBundles(selectors []*common.Selector) (bundles []*bundleutil.Bundle) {
	update := h.Manager.FetchWorkloadUpdate(selectors)

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
