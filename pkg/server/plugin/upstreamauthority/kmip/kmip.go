// Package kmip implements a SPIRE UpstreamAuthority plugin that signs SPIRE's
// intermediate CA certificate via the KMIP Certify operation on a generic
// KMIP 2.1-compliant server (binary TTLV over TCP/TLS).
package kmip

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	ovh "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// init registers the Certify operation payloads with the OVH TTLV runtime.
// This must happen once at package load time so that client.Request() can
// serialise/deserialise the Certify operation.
func init() {
	ovh.RegisterOperationPayload[CertifyRequestPayload, CertifyResponsePayload](ovh.OperationCertify)
}

const pluginName = "kmip"

// BuiltIn returns the catalog.BuiltIn for registering this plugin.
func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		upstreamauthorityv1.UpstreamAuthorityPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// Config is the HCL plugin configuration.
type Config struct {
	// KMIPAddr is the TCP address of the KMIP server (e.g. "kmip.example.com:5696").
	KMIPAddr string `hcl:"kmip_addr"`
	// CACertPath is the PEM file used to verify the KMIP server TLS certificate.
	// Optional; when empty the system certificate pool is used.
	CACertPath string `hcl:"ca_cert_path"`
	// ClientCertPath is the PEM file of the mTLS client certificate.
	ClientCertPath string `hcl:"client_cert_path"`
	// ClientKeyPath is the PEM file of the mTLS client private key.
	ClientKeyPath string `hcl:"client_key_path"`
	// InsecureSkipVerify disables TLS certificate verification (test environments only).
	InsecureSkipVerify bool `hcl:"insecure_skip_verify"`
	// CAKeyUID is the KMIP UniqueIdentifier of the CA private key used to sign CSRs.
	// Required by most KMIP servers (including Eviden KMS) which do not support the
	// KMIP ID Placeholder mechanism for Certify.
	CAKeyUID string `hcl:"ca_key_uid"`
	// CACertUID is the KMIP UniqueIdentifier of the root CA certificate object.
	// Used to populate the upstream X.509 root in MintX509CAAndSubscribe responses.
	// If empty, the plugin attempts to auto-discover it via the CertificateLink on the
	// signed object; if discovery fails, the signed cert is used as a self-anchored root.
	CACertUID string `hcl:"ca_cert_uid"`
}

// Plugin implements the SPIRE UpstreamAuthority using a generic KMIP server.
type Plugin struct {
	upstreamauthorityv1.UnsafeUpstreamAuthorityServer
	configv1.UnsafeConfigServer

	logger    hclog.Logger
	mu        sync.RWMutex
	client    *kmipclient.Client
	caKeyUID  string
	caCertUID string
}

// New returns a new Plugin instance.
func New() *Plugin {
	return &Plugin{}
}

// SetLogger satisfies the hclog.Logger setter interface used by SPIRE.
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.logger = log
}

// Configure parses HCL configuration and dials the KMIP server.
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	cfg, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	if cfg.InsecureSkipVerify {
		p.logger.Warn("TLS certificate verification is disabled; for test environments only")
	}

	client, err := buildClient(cfg)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to connect to KMIP server: %v", err)
	}

	// If ca_cert_uid is not configured, attempt to auto-discover it after the first
	// successful Certify call (done lazily in MintX509CAAndSubscribe).
	p.mu.Lock()
	defer p.mu.Unlock()
	p.client = client
	p.caKeyUID = cfg.CAKeyUID
	p.caCertUID = cfg.CACertUID

	p.logger.Info("KMIP UpstreamAuthority configured", "ca_key_uid", p.caKeyUID, "ca_cert_uid", p.caCertUID)
	return &configv1.ConfigureResponse{}, nil
}

// Validate validates the plugin configuration without applying it.
func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)
	return &configv1.ValidateResponse{Valid: err == nil, Notes: notes}, nil
}

// MintX509CAAndSubscribe signs SPIRE's intermediate CA CSR via KMIP Certify.
// It sends one response on the stream (signed CA chain + upstream root), then
// keeps the stream open until the context is cancelled.
func (p *Plugin) MintX509CAAndSubscribe(req *upstreamauthorityv1.MintX509CARequest, stream upstreamauthorityv1.UpstreamAuthority_MintX509CAAndSubscribeServer) error {
	p.mu.RLock()
	client := p.client
	caKeyUID := p.caKeyUID
	caCertUID := p.caCertUID
	p.mu.RUnlock()

	if client == nil {
		return status.Error(codes.FailedPrecondition, "plugin not configured")
	}

	// Validate the DER-encoded CSR before sending to the KMIP server.
	if _, err := x509.ParseCertificateRequest(req.Csr); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to parse CSR: %v", err)
	}

	certifyResp, err := certify(stream.Context(), client, req.Csr, caKeyUID)
	if err != nil {
		return status.Errorf(codes.Internal, "KMIP Certify failed: %v", err)
	}

	// Retrieve the signed certificate from the KMIP server.
	certBytes, err := getCertificateBytes(stream.Context(), client, certifyResp.UniqueIdentifier)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to retrieve signed certificate: %v", err)
	}

	signedCert, err := parseCertBytes(certBytes)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to parse signed certificate: %v", err)
	}

	// Build the upstream X.509 root.
	var upstreamRoots []*x509.Certificate

	if caCertUID == "" {
		// Attempt to discover the CA cert UID via the CertificateLink on the signed cert object.
		discovered, discoverErr := getLinkedUID(stream.Context(), client, certifyResp.UniqueIdentifier, ovh.LinkTypeCertificateLink)
		if discoverErr == nil {
			caCertUID = discovered
			p.logger.Info("Auto-discovered CA certificate UID", "ca_cert_uid", caCertUID)
			// Cache for future calls.
			p.mu.Lock()
			p.caCertUID = caCertUID
			p.mu.Unlock()
		} else {
			p.logger.Warn("CA cert UID not configured and auto-discovery failed; using signed cert as self-anchored root",
				"err", discoverErr)
		}
	}

	if caCertUID != "" {
		caBytes, err := getCertificateBytes(stream.Context(), client, caCertUID)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to retrieve CA certificate %q: %v", caCertUID, err)
		}
		caCert, err := parseCertBytes(caBytes)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to parse CA certificate %q: %v", caCertUID, err)
		}
		upstreamRoots = []*x509.Certificate{caCert}
	} else {
		upstreamRoots = []*x509.Certificate{signedCert}
	}

	x509CAChain, err := x509certificate.ToPluginFromCertificates([]*x509.Certificate{signedCert})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to form X.509 CA chain: %v", err)
	}

	upstreamX509Roots, err := x509certificate.ToPluginFromCertificates(upstreamRoots)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to form upstream X.509 roots: %v", err)
	}

	if err := stream.Send(&upstreamauthorityv1.MintX509CAResponse{
		X509CaChain:       x509CAChain,
		UpstreamX509Roots: upstreamX509Roots,
	}); err != nil {
		return err
	}

	// Keep the stream open; no live root rotation is implemented.
	<-stream.Context().Done()
	return nil
}

// SubscribeToLocalBundle is not supported.
func (*Plugin) SubscribeToLocalBundle(_ *upstreamauthorityv1.SubscribeToLocalBundleRequest, _ upstreamauthorityv1.UpstreamAuthority_SubscribeToLocalBundleServer) error {
	return status.Error(codes.Unimplemented, "fetching upstream trust bundle is unsupported")
}

// PublishJWTKeyAndSubscribe is not supported.
func (*Plugin) PublishJWTKeyAndSubscribe(_ *upstreamauthorityv1.PublishJWTKeyRequest, _ upstreamauthorityv1.UpstreamAuthority_PublishJWTKeyAndSubscribeServer) error {
	return status.Error(codes.Unimplemented, "publishing upstream JWT keys is unsupported")
}

// ────────────────────────────────────────────────────────────────────────────
// KMIP Certify payload (not yet provided by ovh/kmip-go)
// Ref: KMIP Specification Section 4.6
// ────────────────────────────────────────────────────────────────────────────

// CertifyAttributes holds the KMIP 2.1 Attributes structure (tag 0x420125)
// used in Certify to specify the CA private key link and X.509 extensions.
type CertifyAttributes struct {
	// Link specifies linked objects — used to point to the CA private key.
	Link []ovh.Link
	// VendorAttributes contains vendor-specific attributes.
	// Eviden KMS (Cosmian) uses AttributeName="x509-extension" to inject
	// X.509 extensions (e.g. basic constraints) into the signed certificate.
	// These are serialised as KMIP "Attribute" elements (tag 0x420008).
	VendorAttributes []CertifyVendorAttribute `ttlv:"0x420008"`
}

// CertifyVendorAttribute represents a KMIP Attribute element used for vendor extensions.
type CertifyVendorAttribute struct {
	// VendorIdentification — tag 0x42009D
	VendorIdentification string `ttlv:"0x42009D"`
	// AttributeName — tag 0x42000A
	AttributeName string `ttlv:"0x42000A"`
	// AttributeValue — tag 0x42000B (ByteString)
	AttributeValue []byte `ttlv:"0x42000B"`
}

// caX509Extension is the OpenSSL-style extension string for a KMIP-signed CA certificate.
//
// KMIP's standard Certify request does not provide a portable way to set arbitrary
// X.509 extensions such as basicConstraints: the KMIP CertificateAttributes cover
// subject/issuer fields but not the critical extensions a CA certificate requires.
// Eviden KMS therefore accepts these extensions via the "x509-extension" vendor
// attribute (VendorIdentification="cosmian"), which is required to mark the signed
// certificate as a CA (basicConstraints CA:TRUE).
// Note: cRLSign is omitted — Eviden KMS FIPS mode does not support it.
var caX509Extension = []byte("[v3_ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\n" +
	"keyUsage=critical,keyCertSign,digitalSignature\n")

// CertifyRequestPayload is the KMIP Certify operation request.
// Uses KMIP 2.1 tags since we enforce V2_1 for the UpstreamAuthority connection.
type CertifyRequestPayload struct {
	// CertificateRequestType indicates the format of CertificateRequestValue.
	// Tag 0x420019 — "CertificateRequestType"
	CertificateRequestType ovh.CertificateRequestType
	// CertificateRequestValue holds the DER-encoded PKCS#10 CSR.
	// Tag 0x420140 — "CertificateRequestValue" (KMIP 2.0+).
	CertificateRequestValue []byte `ttlv:"0x420140"`
	// Attributes holds optional attributes for the Certify operation.
	// The CA private key is identified via a PrivateKeyLink here.
	Attributes *CertifyAttributes `ttlv:"0x420125,omitempty"`
}

// Operation satisfies the kmip.OperationPayload interface.
func (p *CertifyRequestPayload) Operation() ovh.Operation {
	return ovh.OperationCertify
}

// CertifyResponsePayload is the KMIP Certify operation response.
type CertifyResponsePayload struct {
	// UniqueIdentifier is the UID of the newly-created Certificate Managed Object.
	UniqueIdentifier string
}

// Operation satisfies the kmip.OperationPayload interface.
func (p *CertifyResponsePayload) Operation() ovh.Operation {
	return ovh.OperationCertify
}

// certify submits a PKCS#10 CSR (DER) to the KMIP server via Certify.
// caKeyUID, if non-empty, is passed as a PrivateKeyLink in the Attributes
// so the server uses it as the signing CA key.
func certify(ctx context.Context, c *kmipclient.Client, csrDER []byte, caKeyUID string) (*CertifyResponsePayload, error) {
	// Always include the CA X.509 extension so the signed cert has basicConstraints CA:TRUE.
	// This uses an Eviden KMS-specific vendor attribute (vendor_identification="cosmian").
	attrs := &CertifyAttributes{
		VendorAttributes: []CertifyVendorAttribute{{
			VendorIdentification: "cosmian",
			AttributeName:        "x509-extension",
			AttributeValue:       caX509Extension,
		}},
	}
	if caKeyUID != "" {
		attrs.Link = []ovh.Link{{
			LinkType:               ovh.LinkTypePrivateKeyLink,
			LinkedObjectIdentifier: caKeyUID,
		}}
	}
	payload := &CertifyRequestPayload{
		CertificateRequestType:  ovh.CertificateRequestTypePKCS_10,
		CertificateRequestValue: csrDER,
		Attributes:              attrs,
	}
	resp, err := c.Request(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("certify request: %w", err)
	}
	certResp, ok := resp.(*CertifyResponsePayload)
	if !ok {
		return nil, fmt.Errorf("unexpected response type %T from Certify", resp)
	}
	return certResp, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ────────────────────────────────────────────────────────────────────────────

// getCertificateBytes fetches a Certificate object from the KMIP server and
// returns the raw DER bytes.
func getCertificateBytes(ctx context.Context, c *kmipclient.Client, uid string) ([]byte, error) {
	getResp, err := c.Get(uid).ExecContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("get certificate %s: %w", uid, err)
	}
	cert, ok := getResp.Object.(*ovh.Certificate)
	if !ok {
		return nil, fmt.Errorf("object %s is %T, expected Certificate", uid, getResp.Object)
	}
	return cert.CertificateValue, nil
}

// getLinkedUID returns the LinkedObjectIdentifier for a Link of the given type
// on the specified KMIP object.
func getLinkedUID(ctx context.Context, c *kmipclient.Client, uid string, linkType ovh.LinkType) (string, error) {
	attrResp, err := c.GetAttributes(uid, ovh.AttributeNameLink).ExecContext(ctx)
	if err != nil {
		return "", fmt.Errorf("GetAttributes(Link) for %s: %w", uid, err)
	}
	for _, attr := range attrResp.Attribute {
		if attr.AttributeName != ovh.AttributeNameLink {
			continue
		}
		link, ok := attr.AttributeValue.(ovh.Link)
		if !ok {
			continue
		}
		if link.LinkType == linkType {
			return link.LinkedObjectIdentifier, nil
		}
	}
	return "", fmt.Errorf("no Link of type %v found on object %s", linkType, uid)
}

// parseCertBytes parses a certificate from DER or PEM bytes.
func parseCertBytes(b []byte) (*x509.Certificate, error) {
	certs, err := pemutil.ParseCertificates(b)
	if err == nil && len(certs) > 0 {
		return certs[0], nil
	}
	return x509.ParseCertificate(b)
}

// ── Config helpers ────────────────────────────────────────────────────────────

// buildConfig is the pluginconf.Builder for this plugin's Config.
func buildConfig(_ catalog.CoreConfig, hclText string, s *pluginconf.Status) *Config {
	cfg := new(Config)
	if err := hcl.Decode(cfg, hclText); err != nil {
		s.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}
	if cfg.KMIPAddr == "" {
		s.ReportError("kmip_addr is required")
	}
	// mTLS is optional: if one field is set, both must be set.
	if cfg.ClientCertPath != "" && cfg.ClientKeyPath == "" {
		s.ReportError("client_key_path is required when client_cert_path is set")
	}
	if cfg.ClientKeyPath != "" && cfg.ClientCertPath == "" {
		s.ReportError("client_cert_path is required when client_key_path is set")
	}
	return cfg
}

// buildClient constructs a kmipclient.Client from the parsed Config.
func buildClient(cfg *Config) (*kmipclient.Client, error) {
	var opts []kmipclient.Option

	if cfg.CACertPath != "" || cfg.InsecureSkipVerify {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // intentional; gated by config
			MinVersion:         tls.VersionTLS12,
		}
		if cfg.CACertPath != "" {
			caPEM, err := os.ReadFile(cfg.CACertPath)
			if err != nil {
				return nil, fmt.Errorf("read CA cert %s: %w", cfg.CACertPath, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				return nil, fmt.Errorf("no valid certificates found in %s", cfg.CACertPath)
			}
			tlsCfg.RootCAs = pool
		}
		opts = append(opts, kmipclient.WithTlsConfig(tlsCfg))
	}

	if cfg.ClientCertPath != "" && cfg.ClientKeyPath != "" {
		opts = append(opts, kmipclient.WithClientCertFiles(cfg.ClientCertPath, cfg.ClientKeyPath))
	}

	// Enforce KMIP 2.1 for the UpstreamAuthority plugin: the Certify operation uses
	// tag 0x420140 (CertificateRequestValue) which is KMIP 2.0+. If the client
	// negotiates KMIP 1.4, the server's KMIP 1.4 parser rejects this tag as unknown.
	opts = append(opts, kmipclient.EnforceVersion(ovh.V2_1))

	return kmipclient.Dial(cfg.KMIPAddr, opts...)
}
