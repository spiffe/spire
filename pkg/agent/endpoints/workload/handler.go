package workload

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang/protobuf/jsonpb"
	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/sirupsen/logrus"
	attestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/api/workload"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	workloadApi = "workload_api"
)

// Handler implements the Workload API interface
type Handler struct {
	Manager manager.Manager
	Catalog catalog.Catalog
	L       logrus.FieldLogger
	M       telemetry.Metrics
}

func (h *Handler) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (resp *workload.JWTSVIDResponse, err error) {
	if len(req.Audience) == 0 {
		return nil, errs.New("audience must be specified")
	}

	_, selectors, metrics, done, err := h.startCall(ctx)
	if err != nil {
		return nil, err
	}
	defer done()

	counter := telemetry.StartCall(metrics, workloadApi, "fetch_jwt_svid")
	defer counter.Done(&err)

	counter.AddLabel("svid_type", "jwt")

	var spiffeIDs []string
	entries := h.Manager.MatchingEntries(selectors)
	if len(entries) == 0 {
		counter.AddLabel("registered", "false")
		return nil, status.Errorf(codes.PermissionDenied, "no identity issued")
	}

	counter.AddLabel("registered", "true")

	for _, entry := range entries {
		if req.SpiffeId != "" && entry.RegistrationEntry.SpiffeId != req.SpiffeId {
			continue
		}
		spiffeIDs = append(spiffeIDs, entry.RegistrationEntry.SpiffeId)
		counter.AddLabel("spiffe_id", entry.RegistrationEntry.SpiffeId)
	}

	resp = new(workload.JWTSVIDResponse)
	for _, spiffeID := range spiffeIDs {
		var svid *client.JWTSVID
		svid, err = h.Manager.FetchJWTSVID(ctx, spiffeID, req.Audience)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "could not fetch %q JWTSVID: %v", spiffeID, err)
		}
		resp.Svids = append(resp.Svids, &workload.JWTSVID{
			SpiffeId: spiffeID,
			Svid:     svid.Token,
		})

		ttl := time.Until(svid.ExpiresAt)
		metrics.SetGaugeWithLabels(
			[]string{workloadApi, "fetch_jwt_svid", "ttl"},
			float32(ttl.Seconds()),
			[]telemetry.Label{
				{Name: "spiffe_id", Value: spiffeID},
			})
	}

	return resp, nil
}

func (h *Handler) FetchJWTBundles(req *workload.JWTBundlesRequest, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	ctx := stream.Context()

	pid, selectors, metrics, done, err := h.startCall(ctx)
	if err != nil {
		return err
	}
	defer done()

	metrics.IncrCounter([]string{workloadApi, "fetch_jwt_bundles"}, 1)

	subscriber := h.Manager.SubscribeToCacheChanges(selectors)
	defer subscriber.Finish()

	for {
		select {
		case update := <-subscriber.Updates():
			metrics.IncrCounter([]string{workloadApi, "bundles_update"}, 1)
			start := time.Now()
			if err := h.sendJWTBundlesResponse(update, stream); err != nil {
				return err
			}

			metrics.MeasureSince([]string{workloadApi, "send_jwt_bundle_latency"}, start)
			if time.Since(start) > (1 * time.Second) {
				h.L.Warnf("Took %v seconds to send JWT bundle to PID %v", time.Since(start).Seconds, pid)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (h *Handler) ValidateJWTSVID(ctx context.Context, req *workload.ValidateJWTSVIDRequest) (*workload.ValidateJWTSVIDResponse, error) {
	if req.Audience == "" {
		return nil, status.Error(codes.InvalidArgument, "audience must be specified")
	}
	if req.Svid == "" {
		return nil, status.Error(codes.InvalidArgument, "svid must be specified")
	}

	_, selectors, metrics, done, err := h.startCall(ctx)
	if err != nil {
		return nil, err
	}
	defer done()

	keyStore := keyStoreFromBundles(h.getWorkloadBundles(selectors))

	spiffeID, claims, err := jwtsvid.ValidateToken(ctx, req.Svid, keyStore, []string{req.Audience})
	if err != nil {
		metrics.IncrCounterWithLabels([]string{workloadApi, "validate_jwt_svid"}, 1, []telemetry.Label{
			{
				Name:  "error",
				Value: err.Error(),
			},
		})
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	metrics.IncrCounterWithLabels([]string{workloadApi, "validate_jwt_svid"}, 1, []telemetry.Label{
		{
			Name:  "subject",
			Value: spiffeID,
		},
		{
			Name:  "audience",
			Value: req.Audience,
		},
	})

	s, err := structFromValues(claims)
	if err != nil {
		return nil, err
	}

	return &workload.ValidateJWTSVIDResponse{
		SpiffeId: spiffeID,
		Claims:   s,
	}, nil

}

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
			err := h.sendX509SVIDResponse(update, stream, metrics, selectors)
			if err != nil {
				return err
			}

			// TODO: evaluate the possibility of removing the following metric at some point
			// in the future because almost the same metric (with different labels and keys) is being
			// taken by the CallCounter in sendX509SVIDResponse function.
			metrics.MeasureSince([]string{workloadApi, "svid_response_latency"}, start)
			if time.Since(start) > (1 * time.Second) {
				h.L.Warnf("Took %v seconds to send SVID response to PID %v", time.Since(start).Seconds, pid)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (h *Handler) sendX509SVIDResponse(update *cache.WorkloadUpdate, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer, metrics telemetry.Metrics, selectors []*common.Selector) (err error) {
	counter := telemetry.StartCall(metrics, workloadApi, "fetch_x509_svid")
	defer counter.Done(&err)

	counter.AddLabel("svid_type", "x509")

	if len(update.Entries) == 0 {
		counter.AddLabel("registered", "false")
		return status.Errorf(codes.PermissionDenied, "no identity issued")
	}

	counter.AddLabel("registered", "true")

	resp, err := h.composeX509SVIDResponse(update)
	if err != nil {
		return status.Errorf(codes.Unavailable, "could not serialize response: %v", err)
	}

	err = stream.Send(resp)
	if err != nil {
		return err
	}

	// Add all the SPIFFE IDs to the labels array.
	for i, svid := range resp.Svids {
		counter.AddLabel("spiffe_id", svid.SpiffeId)

		ttl := time.Until(update.Entries[i].SVID[0].NotAfter)
		metrics.SetGaugeWithLabels(
			[]string{workloadApi, "fetch_x509_svid", "ttl"},
			float32(ttl.Seconds()),
			[]telemetry.Label{
				{Name: "spiffe_id", Value: svid.SpiffeId},
			})
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

func (h *Handler) sendJWTBundlesResponse(update *cache.WorkloadUpdate, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	if len(update.Entries) == 0 {
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
		jwksBytes, err := bundleutil.JWTJWKSBytesFromBundle(update.Bundle)
		if err != nil {
			return nil, err
		}
		bundles[update.Bundle.TrustDomainID()] = jwksBytes
	}

	for _, federatedBundle := range update.FederatedBundles {
		jwksBytes, err := bundleutil.JWTJWKSBytesFromBundle(federatedBundle)
		if err != nil {
			return nil, err
		}
		bundles[federatedBundle.TrustDomainID()] = jwksBytes
	}

	return &workload.JWTBundlesResponse{
		Bundles: bundles,
	}, nil
}

func (h *Handler) startCall(ctx context.Context) (int32, []*common.Selector, telemetry.Metrics, func(), error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(md["workload.spiffe.io"]) != 1 || md["workload.spiffe.io"][0] != "true" {
		return 0, nil, nil, nil, status.Errorf(codes.InvalidArgument, "Security header missing from request")
	}

	watcher, err := h.peerWatcher(ctx)
	if err != nil {
		return 0, nil, nil, nil, status.Errorf(codes.Internal, "Is this a supported system? Please report this bug: %v", err)
	}

	h.M.IncrCounter([]string{workloadApi, "connections"}, 1)

	config := attestor.Config{
		Catalog: h.Catalog,
		L:       h.L,
		M:       h.M,
	}

	selectors := attestor.New(&config).Attest(ctx, watcher.PID())

	// Ensure that the original caller is still alive so that we know we didn't
	// attest some other process that happened to be assigned the original PID
	err = watcher.IsAlive()
	if err != nil {
		return 0, nil, nil, nil, status.Errorf(codes.Unauthenticated, "Could not verify existence of the original caller: %v", err)
	}

	metrics := telemetry.WithLabels(h.M, selectorsToLabels(selectors))
	metrics.IncrCounter([]string{workloadApi, "connection"}, 1)

	done := func() {
		defer h.M.IncrCounter([]string{workloadApi, "connections"}, -1)
	}

	return watcher.PID(), selectors, metrics, done, nil
}

// peerWatcher takes a grpc context, and returns a Watcher representing the caller which
// has issued the request. Returns an error if the call was not made locally, if the necessary
// syscalls aren't unsupported, or if the transport security was not properly configured.
// See the peertracker package for more information.
func (h *Handler) peerWatcher(ctx context.Context) (watcher peertracker.Watcher, err error) {
	watcher, ok := peertracker.WatcherFromContext(ctx)
	if !ok {
		return nil, errors.New("Unable to fetch watcher from context")
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

func selectorsToLabels(selectors []*common.Selector) (labels []telemetry.Label) {
	for _, selector := range selectors {
		labels = append(labels, telemetry.Label{
			Name:  "selector",
			Value: strings.Join([]string{selector.Type, selector.Value}, ":"),
		})
	}
	return labels
}
