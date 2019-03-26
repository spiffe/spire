package sds

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	api_v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	auth_v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	discovery_v2 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/gogo/protobuf/types"
	"github.com/sirupsen/logrus"
	attestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/auth"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/common"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	sdsAPI = "sds_api"
	sdsPID = "sds_pid"
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

	var versionInfo string
	var lastNonce string
	var upd *cache.WorkloadUpdate
	var req *api_v2.DiscoveryRequest
	for {
		select {
		case newReq := <-reqch:
			h.c.Log.WithFields(logrus.Fields{
				"resource_names": newReq.ResourceNames,
				"version_info":   newReq.VersionInfo,
				"nonce":          newReq.ResponseNonce,
			}).Debug("Received StreamSecrets request")
			h.triggerReceivedHook()

			// The nonce should be empty (if we've never sent a response) or
			// match the last sent nonce, otherwise the request should be
			// ignored.
			if lastNonce != "" && lastNonce != newReq.ResponseNonce {
				h.c.Log.Warnf("Received unexpected nonce %q (expected %q); ignoring request", newReq.ResponseNonce, lastNonce)
				continue
			}

			req = newReq

			if upd == nil {
				// Workload update has not been received yet.
				continue
			}
			if req.ErrorDetail != nil {
				// The caller has failed to apply the secrets. Wait until the
				// next update to send down new info.
				h.c.Log.WithFields(logrus.Fields{
					"resource_names": req.ResourceNames,
					"error_detail":   req.ErrorDetail.Message,
				}).Error("Envoy failed to apply secrets")
				continue
			}
			if req.VersionInfo != "" && req.VersionInfo == versionInfo {
				continue
			}
		case upd = <-updch:
			versionInfo = time.Now().UTC().Format(time.RFC3339Nano)
			if req == nil {
				// Nothing has been requested yet.
				continue
			}
		case err := <-errch:
			return err
		}

		resp, err := h.buildResponse(versionInfo, req, upd)
		if err != nil {
			return err
		}

		h.c.Log.WithFields(logrus.Fields{
			"version_info": resp.VersionInfo,
			"nonce":        resp.Nonce,
			"count":        len(resp.Resources),
		}).Debug("Sending StreamSecrets response")
		if err := stream.Send(resp); err != nil {
			return err
		}

		// remember the last nonce and reset the request, preventing another
		// response until the next request comes in.
		lastNonce = resp.Nonce
		req = nil
	}
}

func (h *Handler) FetchSecrets(ctx context.Context, req *api_v2.DiscoveryRequest) (*api_v2.DiscoveryResponse, error) {
	h.c.Log.WithFields(logrus.Fields{
		"resource_names": req.ResourceNames,
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
		"count": len(resp.Resources),
	}).Debug("Sending FetchSecrets response")

	return resp, nil

}

func (h *Handler) startCall(ctx context.Context) (int32, []*common.Selector, func(), error) {
	pid, err := h.callerPID(ctx)
	if err != nil {
		return 0, nil, nil, status.Errorf(codes.Internal, "Is this a supported system? Please report this bug: %v", err)
	}

	metrics := telemetry.WithLabels(h.c.Metrics, []telemetry.Label{{Name: sdsPID, Value: fmt.Sprint(pid)}})
	metrics.IncrCounter([]string{sdsAPI, "connection"}, 1)
	metrics.IncrCounter([]string{sdsAPI, "connections"}, 1)

	selectors := h.c.Attestor.Attest(ctx, pid)

	done := func() {
		defer metrics.IncrCounter([]string{sdsAPI, "connections"}, -1)
	}

	return pid, selectors, done, nil
}

// callerPID takes a grpc context, and returns the PID of the caller which has issued
// the request. Returns an error if the call was not made locally, if the necessary
// syscalls aren't unsupported, or if the transport security was not properly configured.
// See the auth package for more information.
func (h *Handler) callerPID(ctx context.Context) (pid int32, err error) {
	info, ok := auth.CallerFromContext(ctx)
	if !ok {
		return 0, errors.New("unable to fetch credentials from context")
	}

	if info.Err != nil {
		return 0, fmt.Errorf("unable to resolve caller PID: %s", info.Err)
	}

	// If PID is 0, something is wrong...
	if info.PID == 0 {
		return 0, errors.New("unable to resolve caller PID")
	}

	return info.PID, nil
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

	for _, entry := range upd.Entries {
		if len(names) == 0 || names[entry.RegistrationEntry.SpiffeId] {
			tlsCertificate, err := buildTLSCertificate(entry)
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

func buildTLSCertificate(entry *cache.Entry) (*types.Any, error) {
	keyPEM, err := pemutil.EncodePKCS8PrivateKey(entry.PrivateKey)
	if err != nil {
		return nil, err
	}

	certsPEM := pemutil.EncodeCertificates(entry.SVID)

	return types.MarshalAny(&auth_v2.Secret{
		Name: entry.RegistrationEntry.SpiffeId,
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
