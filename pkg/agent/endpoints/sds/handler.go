package sds

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"

	api_v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	auth_v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	discovery_v2 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/gogo/protobuf/types"
	"github.com/sirupsen/logrus"
	attestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_agent "github.com/spiffe/spire/pkg/common/telemetry/agent"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Manager interface {
	SubscribeToCacheChanges(key cache.Selectors) cache.Subscriber
	FetchWorkloadUpdate(selectors []*common.Selector) *cache.WorkloadUpdate
}

type HandlerConfig struct {
	Attestor attestor.Attestor
	Manager  Manager
	Metrics  telemetry.Metrics
	Log      logrus.FieldLogger
}

type Handler struct {
	c HandlerConfig

	hooks struct {
		// test hook used to synchronize receipt of a stream request
		received chan struct{}
	}
}

func NewHandler(config HandlerConfig) *Handler {
	return &Handler{c: config}
}

func (h *Handler) StreamSecrets(stream discovery_v2.SecretDiscoveryService_StreamSecretsServer) error {
	_, selectors, done, err := h.startCall(stream.Context())
	if err != nil {
		return err
	}
	defer done()

	sub := h.c.Manager.SubscribeToCacheChanges(selectors)
	defer sub.Finish()

	updch := sub.Updates()
	reqch := make(chan *api_v2.DiscoveryRequest, 1)
	errch := make(chan error, 1)

	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				if status.Code(err) == codes.Canceled || err == io.EOF {
					err = nil
				}
				errch <- err
				return
			}
			reqch <- req
		}
	}()

	var versionCounter int64
	var versionInfo = strconv.FormatInt(versionCounter, 10)
	var lastNonce string
	var upd *cache.WorkloadUpdate
	var lastReq *api_v2.DiscoveryRequest
	for {
		select {
		case newReq := <-reqch:
			h.c.Log.WithFields(logrus.Fields{
				telemetry.ResourceNames: newReq.ResourceNames,
				telemetry.VersionInfo:   newReq.VersionInfo,
				telemetry.Nonce:         newReq.ResponseNonce,
			}).Debug("Received StreamSecrets request")
			h.triggerReceivedHook()

			// If there's error detail, always log it
			if newReq.ErrorDetail != nil {
				h.c.Log.WithFields(logrus.Fields{
					telemetry.ResourceNames: newReq.ResourceNames,
					telemetry.Error:         newReq.ErrorDetail.Message,
				}).Error("Envoy reported errors applying secrets")
			}

			// If we've previously sent a nonce, this must be a reply
			if lastNonce != "" {

				// The nonce should match the last sent nonce, otherwise
				// it's stale and the request should be ignored.
				if lastNonce != newReq.ResponseNonce {
					h.c.Log.WithFields(logrus.Fields{
						telemetry.Nonce:  newReq.ResponseNonce,
						telemetry.Expect: lastNonce,
					}).Warn("Received unexpected nonce; ignoring request")
					continue
				}

				if newReq.VersionInfo == "" || newReq.VersionInfo != versionInfo {
					// The caller has failed to apply the last update.
					// A NACK might also contain an update to the resource hint, so we need to continue processing.
					h.c.Log.WithFields(logrus.Fields{
						telemetry.VersionInfo: newReq.VersionInfo,
						telemetry.Expect:      versionInfo,
					}).Error("Client rejected expected version and rolled back")
				}

			}

			// We need to send updates if the requested resource list has changed
			// either explicitly, or implicitly because this is the first request.
			var sendUpdates = lastReq == nil || subListChanged(lastReq.ResourceNames, newReq.ResourceNames)

			// save request so that all future workload updates lead to SDS updates for the last request
			lastReq = newReq

			if !sendUpdates {
				continue
			}

			if upd == nil {
				// Workload update has not been received yet, defer sending updates until then
				continue
			}

		case upd = <-updch:
			versionCounter++
			versionInfo = strconv.FormatInt(versionCounter, 10)
			if lastReq == nil {
				// Nothing has been requested yet.
				continue
			}
		case err := <-errch:
			return err
		}

		resp, err := h.buildResponse(versionInfo, lastReq, upd)
		if err != nil {
			return err
		}

		h.c.Log.WithFields(logrus.Fields{
			telemetry.VersionInfo: resp.VersionInfo,
			telemetry.Nonce:       resp.Nonce,
			telemetry.Count:       len(resp.Resources),
		}).Debug("Sending StreamSecrets response")
		if err := stream.Send(resp); err != nil {
			return err
		}

		// remember the last nonce
		lastNonce = resp.Nonce
	}
}

func subListChanged(oldSubs []string, newSubs []string) (b bool) {
	if len(oldSubs) != len(newSubs) {
		return true
	}
	var subMap = make(map[string]bool)
	for _, sub := range oldSubs {
		subMap[sub] = true
	}
	for _, sub := range newSubs {
		if !subMap[sub] {
			return true
		}
	}
	return false
}

func (h *Handler) FetchSecrets(ctx context.Context, req *api_v2.DiscoveryRequest) (*api_v2.DiscoveryResponse, error) {
	h.c.Log.WithFields(logrus.Fields{
		telemetry.ResourceNames: req.ResourceNames,
	}).Debug("Received FetchSecrets request")
	_, selectors, done, err := h.startCall(ctx)
	if err != nil {
		return nil, err
	}
	defer done()

	upd := h.c.Manager.FetchWorkloadUpdate(selectors)

	resp, err := h.buildResponse("", req, upd)
	if err != nil {
		return nil, err
	}

	h.c.Log.WithFields(logrus.Fields{
		telemetry.Count: len(resp.Resources),
	}).Debug("Sending FetchSecrets response")

	return resp, nil

}

// From context, parse out peer watcher PID and selectors. Attest against the PID. Add selectors as labels to
// to a new metrics object. Return this information to the caller so it can emit further metrics.
// If no error, callers must call the output func() to decrement current connections count.
func (h *Handler) startCall(ctx context.Context) (int32, []*common.Selector, func(), error) {
	watcher, err := peerWatcher(ctx)
	if err != nil {
		return 0, nil, nil, status.Errorf(codes.Internal, "Is this a supported system? Please report this bug: %v", err)
	}

	pidStr := fmt.Sprint(watcher.PID())
	metrics := telemetry.WithLabels(h.c.Metrics, []telemetry.Label{{Name: telemetry.SDSPID, Value: fmt.Sprint(pidStr)}})
	telemetry_agent.IncrSDSAPIConnectionCounter(metrics)
	telemetry_agent.IncrSDSAPIConnectionTotalCounter(metrics)
	h.c.Log.WithField(telemetry.SDSPID, pidStr).Debug("Handling SDS API request")

	selectors := h.c.Attestor.Attest(ctx, watcher.PID())

	// Ensure that the original caller is still alive so that we know we didn't
	// attest some other process that happened to be assigned the original PID
	err = watcher.IsAlive()
	if err != nil {
		telemetry_agent.DecrSDSAPIConnectionTotalCounter(metrics)
		h.c.Log.WithField(telemetry.SDSPID, pidStr).Debug("Finished handling SDS API request due to error")
		return 0, nil, nil, status.Errorf(codes.Unauthenticated, "Could not verify existence of the original caller: %v", err)
	}

	done := func() {
		defer telemetry_agent.DecrSDSAPIConnectionTotalCounter(metrics)
		defer h.c.Log.Debug("Finished handling SDS API request")
	}

	return watcher.PID(), selectors, done, nil
}

func (h *Handler) buildResponse(versionInfo string, req *api_v2.DiscoveryRequest, upd *cache.WorkloadUpdate) (resp *api_v2.DiscoveryResponse, err error) {
	resp = &api_v2.DiscoveryResponse{
		TypeUrl:     req.TypeUrl,
		VersionInfo: versionInfo,
	}

	// provide a nonce for streaming requests
	if versionInfo != "" {
		if resp.Nonce, err = nextNonce(); err != nil {
			return nil, err
		}
	}

	// build a convenient set of names for lookups
	names := make(map[string]bool)
	for _, name := range req.ResourceNames {
		names[name] = true
	}

	// TODO: verify the type url

	if upd.Bundle != nil && (len(names) == 0 || names[upd.Bundle.TrustDomainID()]) {
		validationContext, err := buildValidationContext(upd.Bundle)
		if err != nil {
			return nil, err
		}
		resp.Resources = append(resp.Resources, *validationContext)
	}

	for _, federatedBundle := range upd.FederatedBundles {
		if len(names) == 0 || names[federatedBundle.TrustDomainID()] {
			validationContext, err := buildValidationContext(federatedBundle)
			if err != nil {
				return nil, err
			}
			resp.Resources = append(resp.Resources, *validationContext)
		}
	}

	for _, identity := range upd.Identities {
		if len(names) == 0 || names[identity.Entry.SpiffeId] {
			tlsCertificate, err := buildTLSCertificate(identity)
			if err != nil {
				return nil, err
			}
			resp.Resources = append(resp.Resources, *tlsCertificate)
		}
	}

	return resp, nil
}

func (h *Handler) triggerReceivedHook() {
	if h.hooks.received != nil {
		h.hooks.received <- struct{}{}
	}
}

// peerWatcher takes a grpc context, and returns a Watcher representing the caller which
// has issued the request. Returns an error if the call was not made locally, if the necessary
// syscalls aren't unsupported, or if the transport security was not properly configured.
// See the peertracker package for more information.
func peerWatcher(ctx context.Context) (watcher peertracker.Watcher, err error) {
	watcher, ok := peertracker.WatcherFromContext(ctx)
	if !ok {
		return nil, errors.New("unable to fetch watcher from context")
	}

	return watcher, nil
}

func buildTLSCertificate(identity cache.Identity) (*types.Any, error) {
	keyPEM, err := pemutil.EncodePKCS8PrivateKey(identity.PrivateKey)
	if err != nil {
		return nil, err
	}

	certsPEM := pemutil.EncodeCertificates(identity.SVID)

	return types.MarshalAny(&auth_v2.Secret{
		Name: identity.Entry.SpiffeId,
		Type: &auth_v2.Secret_TlsCertificate{
			TlsCertificate: &auth_v2.TlsCertificate{
				CertificateChain: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: certsPEM,
					},
				},
				PrivateKey: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: keyPEM,
					},
				},
			},
		},
	})
}

func buildValidationContext(bundle *bundleutil.Bundle) (*types.Any, error) {
	caBytes := pemutil.EncodeCertificates(bundle.RootCAs())
	return types.MarshalAny(&auth_v2.Secret{
		Name: bundle.TrustDomainID(),
		Type: &auth_v2.Secret_ValidationContext{
			ValidationContext: &auth_v2.CertificateValidationContext{
				TrustedCa: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: caBytes,
					},
				},
			},
		},
	})
}

func nextNonce() (string, error) {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		return "", errs.Wrap(err)
	}
	return hex.EncodeToString(b), nil
}
