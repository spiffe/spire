package sdsv3

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"

	core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secret_v3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	disableSPIFFECertValidationKey = "disable_spiffe_cert_validation"
)

type Attestor interface {
	Attest(ctx context.Context) ([]*common.Selector, error)
}

type Manager interface {
	SubscribeToCacheChanges(ctx context.Context, key cache.Selectors) (cache.Subscriber, error)
	FetchWorkloadUpdate(selectors []*common.Selector) *cache.WorkloadUpdate
}

type Config struct {
	Attestor                    Attestor
	Manager                     Manager
	DefaultAllBundlesName       string
	DefaultBundleName           string
	DefaultSVIDName             string
	DisableSPIFFECertValidation bool
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

func (h *Handler) StreamSecrets(stream secret_v3.SecretDiscoveryService_StreamSecretsServer) error {
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
	reqch := make(chan *discovery_v3.DiscoveryRequest, 1)
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
	var lastReq *discovery_v3.DiscoveryRequest
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

func (h *Handler) DeltaSecrets(secret_v3.SecretDiscoveryService_DeltaSecretsServer) error {
	return status.Error(codes.Unimplemented, "Method is not implemented")
}

func (h *Handler) FetchSecrets(ctx context.Context, req *discovery_v3.DiscoveryRequest) (*discovery_v3.DiscoveryResponse, error) {
	log := rpccontext.Logger(ctx).WithField(telemetry.ResourceNames, req.ResourceNames)

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

func (h *Handler) buildResponse(versionInfo string, req *discovery_v3.DiscoveryRequest, upd *cache.WorkloadUpdate) (resp *discovery_v3.DiscoveryResponse, err error) {
	resp = &discovery_v3.DiscoveryResponse{
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

	builder, err := h.getValidationContextBuilder(req, upd)
	if err != nil {
		return nil, err
	}

	// TODO: verify the type url
	if upd.Bundle != nil {
		switch {
		case returnAllEntries || names[upd.Bundle.TrustDomain().IDString()]:
			validationContext, err := builder.buildOne(upd.Bundle.TrustDomain().IDString(), upd.Bundle.TrustDomain().IDString())
			if err != nil {
				return nil, err
			}

			delete(names, upd.Bundle.TrustDomain().IDString())
			resp.Resources = append(resp.Resources, validationContext)

		case names[h.c.DefaultBundleName]:
			validationContext, err := builder.buildOne(h.c.DefaultBundleName, upd.Bundle.TrustDomain().IDString())
			if err != nil {
				return nil, err
			}

			delete(names, h.c.DefaultBundleName)
			resp.Resources = append(resp.Resources, validationContext)

		case names[h.c.DefaultAllBundlesName]:
			validationContext, err := builder.buildAll(h.c.DefaultAllBundlesName)
			if err != nil {
				return nil, err
			}

			delete(names, h.c.DefaultAllBundlesName)
			resp.Resources = append(resp.Resources, validationContext)
		}
	}

	for td, federatedBundle := range upd.FederatedBundles {
		if returnAllEntries || names[federatedBundle.TrustDomain().IDString()] {
			validationContext, err := builder.buildOne(td.IDString(), td.IDString())
			if err != nil {
				return nil, err
			}
			delete(names, federatedBundle.TrustDomain().IDString())
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
		return nil, status.Errorf(codes.InvalidArgument, "workload is not authorized for the requested identities %q", sortedNames(names))
	}

	return resp, nil
}

func (h *Handler) triggerReceivedHook() {
	if h.hooks.received != nil {
		h.hooks.received <- struct{}{}
	}
}

type validationContextBuilder interface {
	buildOne(resourceName, trustDomainID string) (*any.Any, error)
	buildAll(resourceName string) (*any.Any, error)
}

func (h *Handler) getValidationContextBuilder(req *discovery_v3.DiscoveryRequest, upd *cache.WorkloadUpdate) (validationContextBuilder, error) {
	federatedBundles := make(map[spiffeid.TrustDomain]*spiffebundle.Bundle)
	for td, federatedBundle := range upd.FederatedBundles {
		federatedBundles[td] = federatedBundle
	}
	if !h.isSPIFFECertValidationDisabled(req) && supportsSPIFFEAuthExtension(req) {
		return newSpiffeBuilder(upd.Bundle, federatedBundles)
	}

	return newRootCABuilder(upd.Bundle, federatedBundles), nil
}

type rootCABuilder struct {
	bundles map[string]*spiffebundle.Bundle
}

func newRootCABuilder(bundle *spiffebundle.Bundle, federatedBundles map[spiffeid.TrustDomain]*spiffebundle.Bundle) validationContextBuilder {
	bundles := make(map[string]*spiffebundle.Bundle, len(federatedBundles)+1)
	// Only include tdBundle if it is not nil, which shouldn't ever be the case. This is purely defensive.
	if bundle != nil {
		bundles[bundle.TrustDomain().IDString()] = bundle
	}

	for td, federatedBundle := range federatedBundles {
		bundles[td.IDString()] = federatedBundle
	}

	return &rootCABuilder{
		bundles: bundles,
	}
}

func (b *rootCABuilder) buildOne(resourceName, trustDomain string) (*any.Any, error) {
	bundle, ok := b.bundles[trustDomain]
	if !ok {
		return nil, status.Errorf(codes.Internal, "no bundle found for trust domain: %q", trustDomain)
	}
	caBytes := pemutil.EncodeCertificates(bundle.X509Authorities())
	return anypb.New(&tls_v3.Secret{
		Name: resourceName,
		Type: &tls_v3.Secret_ValidationContext{
			ValidationContext: &tls_v3.CertificateValidationContext{
				TrustedCa: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: caBytes,
					},
				},
			},
		},
	})
}

func (b *rootCABuilder) buildAll(string) (*any.Any, error) {
	return nil, status.Error(codes.Internal, `unable to use "SPIFFE validator" on Envoy below 1.17`)
}

type spiffeBuilder struct {
	bundles map[spiffeid.TrustDomain]*spiffebundle.Bundle
}

func newSpiffeBuilder(tdBundle *spiffebundle.Bundle, federatedBundles map[spiffeid.TrustDomain]*spiffebundle.Bundle) (validationContextBuilder, error) {
	bundles := make(map[spiffeid.TrustDomain]*spiffebundle.Bundle, len(federatedBundles)+1)

	// Only include tdBundle if it is not nil, which shouldn't ever be the case. This is purely defensive.
	if tdBundle != nil {
		bundles[tdBundle.TrustDomain()] = tdBundle
	}

	// Add all federated bundles
	for td, bundle := range federatedBundles {
		bundles[td] = bundle
	}

	return &spiffeBuilder{
		bundles: bundles,
	}, nil
}

func (b *spiffeBuilder) buildOne(resourceName, trustDomainID string) (*any.Any, error) {
	td, err := spiffeid.TrustDomainFromString(trustDomainID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse trustdomain: %v", err)
	}
	bundle, ok := b.bundles[td]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no bundle found for trust domain: %q", trustDomainID)
	}

	caBytes := pemutil.EncodeCertificates(bundle.X509Authorities())
	typedConfig, err := anypb.New(&tls_v3.SPIFFECertValidatorConfig{
		TrustDomains: []*tls_v3.SPIFFECertValidatorConfig_TrustDomain{
			{
				Name: td.Name(),
				TrustBundle: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: caBytes,
					},
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	return anypb.New(&tls_v3.Secret{
		Name: resourceName,
		Type: &tls_v3.Secret_ValidationContext{
			ValidationContext: &tls_v3.CertificateValidationContext{
				CustomValidatorConfig: &core_v3.TypedExtensionConfig{
					Name:        "envoy.tls.cert_validator.spiffe",
					TypedConfig: typedConfig,
				},
			},
		},
	})
}

func (b *spiffeBuilder) buildAll(resourceName string) (*any.Any, error) {
	configTrustDomains := []*tls_v3.SPIFFECertValidatorConfig_TrustDomain{}

	// Create SPIFFE validator config
	for td, bundle := range b.bundles {
		// bundle := bundles[td]
		caBytes := pemutil.EncodeCertificates(bundle.X509Authorities())
		configTrustDomains = append(configTrustDomains, &tls_v3.SPIFFECertValidatorConfig_TrustDomain{
			Name: td.Name(),
			TrustBundle: &core_v3.DataSource{
				Specifier: &core_v3.DataSource_InlineBytes{
					InlineBytes: caBytes,
				},
			},
		})
	}

	// // Order by trustdomain name to return in consistent order
	sort.Slice(configTrustDomains, func(i, j int) bool {
		return configTrustDomains[i].Name < configTrustDomains[j].Name
	})

	typedConfig, err := anypb.New(&tls_v3.SPIFFECertValidatorConfig{
		TrustDomains: configTrustDomains,
	})
	if err != nil {
		return nil, err
	}

	return anypb.New(&tls_v3.Secret{
		Name: resourceName,
		Type: &tls_v3.Secret_ValidationContext{
			ValidationContext: &tls_v3.CertificateValidationContext{
				CustomValidatorConfig: &core_v3.TypedExtensionConfig{
					Name:        "envoy.tls.cert_validator.spiffe",
					TypedConfig: typedConfig,
				},
			},
		},
	})
}

func supportsSPIFFEAuthExtension(req *discovery_v3.DiscoveryRequest) bool {
	if buildVersion := req.Node.GetUserAgentBuildVersion(); buildVersion != nil {
		version := buildVersion.Version
		return (version.MajorNumber == 1 && version.MinorNumber > 17) || version.MajorNumber > 1
	}
	return false
}

func (h *Handler) isSPIFFECertValidationDisabled(req *discovery_v3.DiscoveryRequest) bool {
	disabled := h.c.DisableSPIFFECertValidation
	if v, ok := req.Node.GetMetadata().GetFields()[disableSPIFFECertValidationKey]; ok {
		// error means that field have some unexpected value
		// so it would be safer to assume that key doesn't exist in envoy node metadata
		if override, err := parseBool(v); err == nil {
			disabled = override
		}
	}

	return disabled
}

func parseBool(v *structpb.Value) (bool, error) {
	switch v := v.GetKind().(type) {
	case *structpb.Value_BoolValue:
		return v.BoolValue, nil
	case *structpb.Value_StringValue:
		return strconv.ParseBool(v.StringValue)
	}

	return false, fmt.Errorf("unsupported value type %T", v)
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

	return anypb.New(&tls_v3.Secret{
		Name: name,
		Type: &tls_v3.Secret_TlsCertificate{
			TlsCertificate: &tls_v3.TlsCertificate{
				CertificateChain: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: certsPEM,
					},
				},
				PrivateKey: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: keyPEM,
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
