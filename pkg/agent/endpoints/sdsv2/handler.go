package sdsv2

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strconv"

	api_v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	auth_v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	core_v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	discovery_v2 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

type Attestor interface {
	Attest(ctx context.Context) ([]*common.Selector, error)
}

type Manager interface {
	SubscribeToCacheChanges(ctx context.Context, key cache.Selectors) (cache.Subscriber, error)
	FetchWorkloadUpdate(selectors []*common.Selector) *cache.WorkloadUpdate
}

type Config struct {
	Attestor          Attestor
	Manager           Manager
	DefaultBundleName string
	DefaultSVIDName   string
}

type Handler struct {
	c Config

	hooks struct {
		// test hook used to synchronize receipt of a stream request
		received chan struct{}
	}
}

func New(config Config) *Handler {
	return &Handler{c: config}
}

func (h *Handler) StreamSecrets(stream discovery_v2.SecretDiscoveryService_StreamSecretsServer) error {
	log := rpccontext.Logger(stream.Context())

	selectors, err := h.c.Attestor.Attest(stream.Context())
	if err != nil {
		log.WithError(err).Error("Failed to attest the workload")
		return err
	}

	sub, err := h.c.Manager.SubscribeToCacheChanges(stream.Context(), selectors)
	if err != nil {
		log.WithError(err).Error("Subscribe to cache changes failed")
		return err
	}
	defer sub.Finish()

	updch := sub.Updates()
	reqch := make(chan *api_v2.DiscoveryRequest, 1)
	errch := make(chan error, 1)

	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				if status.Code(err) == codes.Canceled || errors.Is(err, io.EOF) {
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
			log.WithFields(logrus.Fields{
				telemetry.ResourceNames: newReq.ResourceNames,
				telemetry.VersionInfo:   newReq.VersionInfo,
				telemetry.Nonce:         newReq.ResponseNonce,
			}).Debug("Received StreamSecrets request")
			h.triggerReceivedHook()

			// If there's error detail, always log it
			if newReq.ErrorDetail != nil {
				log.WithFields(logrus.Fields{
					telemetry.ResourceNames: newReq.ResourceNames,
					telemetry.Error:         newReq.ErrorDetail.Message,
				}).Error("Envoy reported errors applying secrets")
			}

			// If we've previously sent a nonce, this must be a reply
			if lastNonce != "" {
				// The nonce should match the last sent nonce, otherwise
				// it's stale and the request should be ignored.
				if lastNonce != newReq.ResponseNonce {
					log.WithFields(logrus.Fields{
						telemetry.Nonce:  newReq.ResponseNonce,
						telemetry.Expect: lastNonce,
					}).Warn("Received unexpected nonce; ignoring request")
					continue
				}

				if newReq.VersionInfo == "" || newReq.VersionInfo != versionInfo {
					// The caller has failed to apply the last update.
					// A NACK might also contain an update to the resource hint, so we need to continue processing.
					log.WithFields(logrus.Fields{
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
			log.WithError(err).Error("Received error from stream secrets server")
			return err
		}

		resp, err := h.buildResponse(versionInfo, lastReq, upd)
		if err != nil {
			log.WithError(err).Error("Error building stream secrets response")
			return err
		}

		log.WithFields(logrus.Fields{
			telemetry.VersionInfo: resp.VersionInfo,
			telemetry.Nonce:       resp.Nonce,
			telemetry.Count:       len(resp.Resources),
		}).Debug("Sending StreamSecrets response")
		if err := stream.Send(resp); err != nil {
			log.WithError(err).Error("Error sending secrets over stream")
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

func (h *Handler) DeltaSecrets(discovery_v2.SecretDiscoveryService_DeltaSecretsServer) error {
	return status.Error(codes.Unimplemented, "Method is not implemented")
}

func (h *Handler) FetchSecrets(ctx context.Context, req *api_v2.DiscoveryRequest) (*api_v2.DiscoveryResponse, error) {
	log := rpccontext.Logger(ctx).WithFields(logrus.Fields{
		telemetry.ResourceNames: req.ResourceNames,
	})

	selectors, err := h.c.Attestor.Attest(ctx)
	if err != nil {
		log.WithError(err).Error("Failed to attest the workload")
		return nil, err
	}

	upd := h.c.Manager.FetchWorkloadUpdate(selectors)

	resp, err := h.buildResponse("", req, upd)
	if err != nil {
		log.WithError(err).Error("Error building fetch secrets response")
		return nil, err
	}

	log.WithFields(logrus.Fields{
		telemetry.Count: len(resp.Resources),
	}).Debug("Sending FetchSecrets response")

	return resp, nil
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
		if name != "" {
			names[name] = true
		}
	}
	returnAllEntries := len(names) == 0

	// TODO: verify the type url
	if upd.Bundle != nil {
		switch {
		case returnAllEntries || names[upd.Bundle.TrustDomainID()]:
			validationContext, err := buildValidationContext(upd.Bundle, "")
			if err != nil {
				return nil, err
			}
			delete(names, upd.Bundle.TrustDomainID())
			resp.Resources = append(resp.Resources, validationContext)
		case names[h.c.DefaultBundleName]:
			validationContext, err := buildValidationContext(upd.Bundle, h.c.DefaultBundleName)
			if err != nil {
				return nil, err
			}
			delete(names, h.c.DefaultBundleName)
			resp.Resources = append(resp.Resources, validationContext)
		}
	}

	for _, federatedBundle := range upd.FederatedBundles {
		if returnAllEntries || names[federatedBundle.TrustDomainID()] {
			validationContext, err := buildValidationContext(federatedBundle, "")
			if err != nil {
				return nil, err
			}
			delete(names, federatedBundle.TrustDomainID())
			resp.Resources = append(resp.Resources, validationContext)
		}
	}

	for i, identity := range upd.Identities {
		switch {
		case returnAllEntries || names[identity.Entry.SpiffeId]:
			tlsCertificate, err := buildTLSCertificate(identity, "")
			if err != nil {
				return nil, err
			}
			delete(names, identity.Entry.SpiffeId)
			resp.Resources = append(resp.Resources, tlsCertificate)
		case i == 0 && names[h.c.DefaultSVIDName]:
			tlsCertificate, err := buildTLSCertificate(identity, h.c.DefaultSVIDName)
			if err != nil {
				return nil, err
			}
			delete(names, h.c.DefaultSVIDName)
			resp.Resources = append(resp.Resources, tlsCertificate)
		}
	}

	if len(names) > 0 {
		return nil, errs.New("workload is not authorized for the requested identities %q", sortedNames(names))
	}

	return resp, nil
}

func (h *Handler) triggerReceivedHook() {
	if h.hooks.received != nil {
		h.hooks.received <- struct{}{}
	}
}

func buildTLSCertificate(identity cache.Identity, defaultSVIDName string) (*anypb.Any, error) {
	name := identity.Entry.SpiffeId
	if defaultSVIDName != "" {
		name = defaultSVIDName
	}

	keyPEM, err := pemutil.EncodePKCS8PrivateKey(identity.PrivateKey)
	if err != nil {
		return nil, err
	}

	certsPEM := pemutil.EncodeCertificates(identity.SVID)

	return anypb.New(&auth_v2.Secret{
		Name: name,
		Type: &auth_v2.Secret_TlsCertificate{
			TlsCertificate: &auth_v2.TlsCertificate{
				CertificateChain: &core_v2.DataSource{
					Specifier: &core_v2.DataSource_InlineBytes{
						InlineBytes: certsPEM,
					},
				},
				PrivateKey: &core_v2.DataSource{
					Specifier: &core_v2.DataSource_InlineBytes{
						InlineBytes: keyPEM,
					},
				},
			},
		},
	})
}

func buildValidationContext(bundle *bundleutil.Bundle, defaultBundleName string) (*anypb.Any, error) {
	name := bundle.TrustDomainID()
	if defaultBundleName != "" {
		name = defaultBundleName
	}
	caBytes := pemutil.EncodeCertificates(bundle.RootCAs())
	return anypb.New(&auth_v2.Secret{
		Name: name,
		Type: &auth_v2.Secret_ValidationContext{
			ValidationContext: &auth_v2.CertificateValidationContext{
				TrustedCa: &core_v2.DataSource{
					Specifier: &core_v2.DataSource_InlineBytes{
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

func sortedNames(names map[string]bool) []string {
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
