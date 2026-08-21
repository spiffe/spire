package evidenkms

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	kmip "github.com/Cosmian/kmip-go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const pluginName = "eviden_kms"

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
	// KMSAddr is the base URL of Eviden KMS.
	KMSAddr string `hcl:"kms_addr"`
	// CACertPath is the PEM file used to verify the KMS TLS certificate.
	CACertPath string `hcl:"ca_cert_path"`
	// InsecureSkipVerify disables TLS certificate verification (test environments only).
	InsecureSkipVerify bool `hcl:"insecure_skip_verify"`
	// CAKeyUID is the KMIP UniqueIdentifier of the root CA private key stored in the KMS.
	// The key must have been created and tagged before SPIRE starts.
	CAKeyUID string `hcl:"ca_key_uid"`
	// CACertUID is the KMIP UniqueIdentifier of the root CA certificate stored in the KMS.
	// Used to populate the upstream X.509 root in MintX509CAAndSubscribe responses.
	// If empty, the signed certificate is used as a self-anchored root (not recommended).
	CACertUID string `hcl:"ca_cert_uid"`

	// CertAuth configures mTLS client certificate authentication.
	CertAuth *certAuthConfig `hcl:"cert_auth"`
	// TokenAuth configures static Bearer token / API key authentication.
	TokenAuth *tokenAuthConfig `hcl:"token_auth"`
}

type certAuthConfig struct {
	ClientCertPath string `hcl:"client_cert_path"`
	ClientKeyPath  string `hcl:"client_key_path"`
}

type tokenAuthConfig struct {
	Token string `hcl:"token"`
}

// Plugin implements the SPIRE UpstreamAuthority using Eviden KMS.
type Plugin struct {
	upstreamauthorityv1.UnsafeUpstreamAuthorityServer
	configv1.UnsafeConfigServer

	logger    hclog.Logger
	mu        sync.RWMutex
	client    *kmip.Client
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

// Configure parses HCL configuration and initialises the KMS client.
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	cfg, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	if cfg.InsecureSkipVerify {
		p.logger.Warn("TLS verification of KMS certificates is skipped; for test environments only")
	}

	kmsClient, err := buildKMSClient(cfg)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to create KMS client: %v", err)
	}

	caCertUID := cfg.CACertUID
	if caCertUID == "" {
		// Auto-discover the CA certificate UID from the CertificateLink on the CA private key.
		// This is set automatically when CreateSelfSignedCertificate is called on the CA key.
		discovered, discoverErr := kmsClient.GetLinkedCertificateUID(ctx, cfg.CAKeyUID)
		if discoverErr != nil {
			p.logger.Warn("CA cert UID not configured and auto-discovery failed; "+
				"MintX509CAAndSubscribe will return the signed cert as a self-anchored root",
				"ca_key_uid", cfg.CAKeyUID, "err", discoverErr)
		} else {
			caCertUID = discovered
			p.logger.Info("Auto-discovered CA certificate UID from key link", "ca_cert_uid", caCertUID)
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.client = kmsClient
	p.caKeyUID = cfg.CAKeyUID
	p.caCertUID = caCertUID

	p.logger.Info("Eviden KMS UpstreamAuthority configured",
		"ca_key_uid", p.caKeyUID,
		"ca_cert_uid", p.caCertUID)
	return &configv1.ConfigureResponse{}, nil
}

// Validate validates the plugin configuration without applying it.
func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)
	return &configv1.ValidateResponse{Valid: err == nil, Notes: notes}, nil
}

// MintX509CAAndSubscribe signs SPIRE's intermediate CA CSR via the KMS Certify operation.
// It sends one response on the stream with the signed CA chain and upstream root, then
// keeps the stream open until the context is cancelled (no live root rotation).
func (p *Plugin) MintX509CAAndSubscribe(req *upstreamauthorityv1.MintX509CARequest, stream upstreamauthorityv1.UpstreamAuthority_MintX509CAAndSubscribeServer) error {
	p.mu.RLock()
	client := p.client
	caKeyUID := p.caKeyUID
	caCertUID := p.caCertUID
	p.mu.RUnlock()

	if client == nil {
		return status.Error(codes.FailedPrecondition, "plugin not configured")
	}

	// Parse the DER-encoded CSR to validate it before sending to KMS.
	if _, err := x509.ParseCertificateRequest(req.Csr); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to parse CSR: %v", err)
	}

	// Encode CSR as PEM for the KMS Certify operation.
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: req.Csr})

	// Note: req.PreferredTtl is acknowledged but not forwarded to the KMS. The Eviden KMS
	// Certify operation does not accept a validity period alongside CSR-based requests
	// without the full certificate subject. CA certificate TTL is controlled by the KMS
	// server configuration (see github.com/Cosmian/kmip-go for details).
	certifyResp, err := client.Certify(stream.Context(), csrPEM, caKeyUID, caCertUID,
		[]byte("[v3_ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,crlSign,digitalSignature\n"))
	if err != nil {
		return status.Errorf(codes.Internal, "failed to certify CSR: %v", err)
	}

	// Retrieve the signed certificate bytes from the KMS.
	certBytes, err := client.ExportCertificate(stream.Context(), certifyResp.CertUID)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to export certificate: %v", err)
	}

	// certBytes may be DER or PEM depending on the KMS response; normalise to *x509.Certificate.
	signedCert, err := parseCertBytes(certBytes)
	if err != nil {
		return status.Errorf(codes.Internal, "parse signed certificate: %v", err)
	}

	// Retrieve the issuing CA certificate to form the upstream root.
	var upstreamRoots []*x509.Certificate
	if caCertUID != "" {
		caChainResp, err := client.ExportCertificate(stream.Context(), caCertUID)
		if err != nil {
			// ca_cert_uid is explicitly configured; fail fast rather than return empty roots.
			return status.Errorf(codes.Internal, "failed to retrieve configured CA certificate %q: %v", caCertUID, err)
		}
		caCert, err := parseCertBytes(caChainResp)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to parse configured CA certificate %q: %v", caCertUID, err)
		}
		upstreamRoots = []*x509.Certificate{caCert}
	} else {
		// No CA cert UID: use the signed cert as a self-anchored root (single-tier CA).
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

	// Keep stream open until the context is cancelled. No live root rotation.
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
// Internal helpers
// ────────────────────────────────────────────────────────────────────────────

func buildConfig(_ catalog.CoreConfig, hclText string, s *pluginconf.Status) *Config {
	cfg := new(Config)
	if err := hcl.Decode(cfg, hclText); err != nil {
		s.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}
	if cfg.KMSAddr == "" {
		s.ReportError("kms_addr is required")
	}
	if cfg.CAKeyUID == "" {
		s.ReportError("ca_key_uid is required")
	}
	if cfg.CertAuth != nil && cfg.TokenAuth != nil {
		s.ReportError("cert_auth and token_auth are mutually exclusive")
	}
	if cfg.CertAuth == nil && cfg.TokenAuth == nil {
		s.ReportError("one of cert_auth or token_auth must be configured")
	}
	return cfg
}

func buildKMSClient(cfg *Config) (*kmip.Client, error) {
	kmipCfg := &kmip.Config{
		KMSAddr:            cfg.KMSAddr,
		CACertPath:         cfg.CACertPath,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}
	if cfg.CertAuth != nil {
		kmipCfg.CertAuth = &kmip.CertAuthConfig{
			ClientCertPath: cfg.CertAuth.ClientCertPath,
			ClientKeyPath:  cfg.CertAuth.ClientKeyPath,
		}
	}
	if cfg.TokenAuth != nil {
		kmipCfg.TokenAuth = &kmip.TokenAuthConfig{Token: cfg.TokenAuth.Token}
	}
	return kmip.NewClient(kmipCfg)
}

// parseCertBytes parses a certificate that may be DER-encoded bytes or PEM-encoded bytes.
func parseCertBytes(b []byte) (*x509.Certificate, error) {
	// Try PEM first.
	if cert, err := pemutil.ParseCertificate(b); err == nil {
		return cert, nil
	}
	// Fall back to DER.
	return x509.ParseCertificate(b)
}
