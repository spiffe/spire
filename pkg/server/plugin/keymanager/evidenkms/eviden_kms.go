package evidenkms

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
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
		keymanagerv1.KeyManagerPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// Config is the HCL plugin configuration.
type Config struct {
	// KMSAddr is the base URL of Eviden KMS (e.g. "https://kms.example.com:9998").
	KMSAddr string `hcl:"kms_addr"`
	// CACertPath is the PEM file used to verify the KMS TLS certificate.
	CACertPath string `hcl:"ca_cert_path"`
	// InsecureSkipVerify disables TLS certificate verification (test environments only).
	InsecureSkipVerify bool `hcl:"insecure_skip_verify"`
	// ServerID is a stable identifier for this SPIRE server instance. All keys created
	// by this plugin are tagged with "x-spire-server-id:<ServerID>" so they can be
	// recovered on restart via Locate.
	ServerID string `hcl:"server_id"`

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

// keyEntry maps a SPIRE key ID to the KMS private key UID and the cached public key.
type keyEntry struct {
	privateKeyUID string
	publicKey     *keymanagerv1.PublicKey
}

// Plugin implements the SPIRE KeyManager using Eviden KMS.
type Plugin struct {
	keymanagerv1.UnsafeKeyManagerServer
	configv1.UnsafeConfigServer

	logger   hclog.Logger
	mu       sync.RWMutex
	entries  map[string]keyEntry // spireKeyID → keyEntry
	serverID string
	client   *kmip.Client
}

// New returns a new Plugin instance.
func New() *Plugin {
	return &Plugin{
		entries: make(map[string]keyEntry),
	}
}

// SetLogger satisfies the hclog.Logger setter interface used by SPIRE.
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.logger = log
}

// Configure parses HCL config, builds the KMS client, and recovers existing
// keys from the KMS via Locate.
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

	p.mu.Lock()
	defer p.mu.Unlock()

	p.client = kmsClient
	p.serverID = cfg.ServerID
	p.entries = make(map[string]keyEntry)

	// Recover existing keys from KMS so we survive SPIRE server restarts.
	if err := p.recoverKeys(ctx); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to recover keys from KMS: %v", err)
	}

	p.logger.Info("Eviden KMS KeyManager configured", "server_id", p.serverID, "keys_recovered", len(p.entries))
	return &configv1.ConfigureResponse{}, nil
}

// Validate validates the plugin configuration without applying it.
func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)
	return &configv1.ValidateResponse{Valid: err == nil, Notes: notes}, nil
}

// GenerateKey creates a new asymmetric key pair in Eviden KMS.
func (p *Plugin) GenerateKey(ctx context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.KeyType == keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE {
		return nil, status.Error(codes.InvalidArgument, "key type is required")
	}

	// Snapshot mutable state under RLock so GenerateKey doesn't race with Configure.
	p.mu.RLock()
	client := p.client
	serverID := p.serverID
	p.mu.RUnlock()
	if client == nil {
		return nil, status.Error(codes.FailedPrecondition, "plugin not configured")
	}

	kt, err := toKMIPKeyType(req.KeyType)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	// Store three metadata tags: server-id, spire-key-id, and key-type.
	// All three are needed to reconstruct the full PublicKey on restart.
	tags := []string{
		serverIDTag(serverID),
		spireKeyIDTag(req.KeyId),
		spireKeyTypeTag(req.KeyType),
	}

	resp, err := client.CreateKeyPair(ctx, kt, tags)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create key pair: %v", err)
	}

	attrResp, err := client.GetPublicKey(ctx, resp.PublicKeyUID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get public key after create: %v", err)
	}

	pk := &keymanagerv1.PublicKey{
		Id:          req.KeyId,
		Type:        req.KeyType,
		PkixData:    attrResp.PublicKeyPKIX,
		Fingerprint: fingerprint(attrResp.PublicKeyPKIX),
	}

	p.mu.Lock()
	// Schedule deletion of the old key if one already exists for this key ID.
	if old, ok := p.entries[req.KeyId]; ok {
		go func() {
			if err := client.Destroy(context.Background(), old.privateKeyUID); err != nil {
				p.logger.Warn("Failed to destroy old key", "uid", old.privateKeyUID, "err", err)
			}
		}()
	}
	p.entries[req.KeyId] = keyEntry{privateKeyUID: resp.PrivateKeyUID, publicKey: pk}
	p.mu.Unlock()

	return &keymanagerv1.GenerateKeyResponse{PublicKey: pk}, nil
}

// SignData signs pre-hashed data using the private key identified by req.KeyId.
func (p *Plugin) SignData(ctx context.Context, req *keymanagerv1.SignDataRequest) (*keymanagerv1.SignDataResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.SignerOpts == nil {
		return nil, status.Error(codes.InvalidArgument, "signer opts is required")
	}

	p.mu.RLock()
	client := p.client
	entry, ok := p.entries[req.KeyId]
	p.mu.RUnlock()
	if client == nil {
		return nil, status.Error(codes.FailedPrecondition, "plugin not configured")
	}
	if !ok {
		return nil, status.Errorf(codes.NotFound, "key %q not found", req.KeyId)
	}

	hashAlgo, sigAlgo, err := toKMIPSignParams(entry.publicKey.Type, req.SignerOpts)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	sig, err := client.Sign(ctx, entry.privateKeyUID, req.Data, hashAlgo, sigAlgo)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to sign data: %v", err)
	}

	return &keymanagerv1.SignDataResponse{Signature: sig, KeyFingerprint: entry.publicKey.Fingerprint}, nil
}

// GetPublicKey returns the cached public key for the given SPIRE key ID.
func (p *Plugin) GetPublicKey(_ context.Context, req *keymanagerv1.GetPublicKeyRequest) (*keymanagerv1.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}

	p.mu.RLock()
	entry, ok := p.entries[req.KeyId]
	p.mu.RUnlock()
	if !ok {
		return nil, status.Errorf(codes.NotFound, "key %q not found", req.KeyId)
	}

	return &keymanagerv1.GetPublicKeyResponse{PublicKey: entry.publicKey}, nil
}

// GetPublicKeys returns all cached public keys owned by this SPIRE server.
func (p *Plugin) GetPublicKeys(_ context.Context, _ *keymanagerv1.GetPublicKeysRequest) (*keymanagerv1.GetPublicKeysResponse, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	keys := make([]*keymanagerv1.PublicKey, 0, len(p.entries))
	for _, e := range p.entries {
		keys = append(keys, e.publicKey)
	}

	return &keymanagerv1.GetPublicKeysResponse{PublicKeys: keys}, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ────────────────────────────────────────────────────────────────────────────

// recoverKeys fetches all private keys tagged with this server's ID from the KMS
// and rebuilds the in-memory entries map. Called under p.mu lock.
func (p *Plugin) recoverKeys(ctx context.Context) error {
	uids, err := p.client.Locate(ctx, []string{serverIDTag(p.serverID)})
	if err != nil {
		return fmt.Errorf("failed to locate keys: %w", err)
	}

	for _, privUID := range uids {
		// Read all cosmian vendor tags to recover the SPIRE key ID and key type.
		tags, err := p.client.GetVendorTags(ctx, privUID)
		if err != nil {
			p.logger.Warn("Failed to read tags during recovery", "priv_uid", privUID, "err", err)
			continue
		}

		spireKeyID := tagValue(tags, "x-spire-key-id:")
		if spireKeyID == "" {
			p.logger.Warn("Key has no x-spire-key-id tag; skipping recovery", "priv_uid", privUID)
			continue
		}

		keyType, err := tagValueToKeyType(tagValue(tags, "x-spire-key-type:"))
		if err != nil {
			p.logger.Warn("Key has unknown or missing x-spire-key-type tag; skipping recovery",
				"priv_uid", privUID, "tag", tagValue(tags, "x-spire-key-type:"))
			continue
		}

		// Resolve the linked public key UID.
		pubUID, err := p.client.GetLinkedPublicKeyUID(ctx, privUID)
		if err != nil {
			p.logger.Warn("Failed to resolve public key UID during recovery", "priv_uid", privUID, "err", err)
			continue
		}

		attrResp, err := p.client.GetPublicKey(ctx, pubUID)
		if err != nil {
			p.logger.Warn("Failed to recover public key", "pub_uid", pubUID, "err", err)
			continue
		}

		pk := &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    attrResp.PublicKeyPKIX,
			Fingerprint: fingerprint(attrResp.PublicKeyPKIX),
		}
		p.entries[spireKeyID] = keyEntry{privateKeyUID: privUID, publicKey: pk}
		p.logger.Debug("Recovered key", "spire_key_id", spireKeyID, "key_type", keyType, "priv_uid", privUID)
	}
	return nil
}

// tagValue finds the value part of a tag with the given prefix (e.g. "x-spire-key-id:").
func tagValue(tags []string, prefix string) string {
	for _, t := range tags {
		if len(t) > len(prefix) && t[:len(prefix)] == prefix {
			return t[len(prefix):]
		}
	}
	return ""
}

// tagValueToKeyType converts a stored key-type tag value back to a SPIRE KeyType.
// Returns an error for unknown or missing values to prevent silent misclassification
// during key recovery.
func tagValueToKeyType(s string) (keymanagerv1.KeyType, error) {
	switch s {
	case "EC_P256":
		return keymanagerv1.KeyType_EC_P256, nil
	case "EC_P384":
		return keymanagerv1.KeyType_EC_P384, nil
	case "RSA_2048":
		return keymanagerv1.KeyType_RSA_2048, nil
	case "RSA_4096":
		return keymanagerv1.KeyType_RSA_4096, nil
	default:
		return keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE, fmt.Errorf("unknown key type tag %q", s)
	}
}

// buildConfig is the pluginconf.Builder for this plugin's Config.
func buildConfig(_ catalog.CoreConfig, hclText string, s *pluginconf.Status) *Config {
	cfg := new(Config)
	if err := hcl.Decode(cfg, hclText); err != nil {
		s.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}
	if cfg.KMSAddr == "" {
		s.ReportError("kms_addr is required")
	}
	if cfg.ServerID == "" {
		s.ReportError("server_id is required")
	}
	if cfg.CertAuth != nil && cfg.TokenAuth != nil {
		s.ReportError("cert_auth and token_auth are mutually exclusive")
	}
	if cfg.CertAuth == nil && cfg.TokenAuth == nil {
		s.ReportError("one of cert_auth or token_auth must be configured")
	}
	return cfg
}

// buildKMSClient constructs a *kmip.Client from the parsed Config.
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

// toKMIPKeyType maps a SPIRE KeyType to a kmip.KeyType.
func toKMIPKeyType(kt keymanagerv1.KeyType) (kmip.KeyType, error) {
	switch kt {
	case keymanagerv1.KeyType_EC_P256:
		return kmip.KeyTypeECP256, nil
	case keymanagerv1.KeyType_EC_P384:
		return kmip.KeyTypeECP384, nil
	case keymanagerv1.KeyType_RSA_2048:
		return kmip.KeyTypeRSA2048, nil
	case keymanagerv1.KeyType_RSA_4096:
		return kmip.KeyTypeRSA4096, nil
	default:
		return "", fmt.Errorf("unsupported key type: %v", kt)
	}
}

// toKMIPSignParams derives the KMIP hash and signature algorithm from a SPIRE SignerOpts.
func toKMIPSignParams(kt keymanagerv1.KeyType, opts any) (kmip.HashAlgorithm, kmip.SignatureAlgorithm, error) {
	switch o := opts.(type) {
	case *keymanagerv1.SignDataRequest_HashAlgorithm:
		hash, err := toKMIPHashAlgo(o.HashAlgorithm)
		if err != nil {
			return "", "", err
		}
		sigAlgo := kmip.SigECDSA
		if kt == keymanagerv1.KeyType_RSA_2048 || kt == keymanagerv1.KeyType_RSA_4096 {
			sigAlgo = kmip.SigRSAPKCS1
		}
		return hash, sigAlgo, nil
	case *keymanagerv1.SignDataRequest_PssOptions:
		hash, err := toKMIPHashAlgo(o.PssOptions.HashAlgorithm)
		if err != nil {
			return "", "", err
		}
		return hash, kmip.SigRSAPSS, nil
	default:
		return "", "", fmt.Errorf("unsupported signer opts type %T", opts)
	}
}

func toKMIPHashAlgo(h keymanagerv1.HashAlgorithm) (kmip.HashAlgorithm, error) {
	switch h {
	case keymanagerv1.HashAlgorithm_SHA256:
		return kmip.HashSHA256, nil
	case keymanagerv1.HashAlgorithm_SHA384:
		return kmip.HashSHA384, nil
	case keymanagerv1.HashAlgorithm_SHA512:
		return kmip.HashSHA512, nil
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %v", h)
	}
}

// Tag helpers — SPIRE metadata stored as KMS vendor tags.
func serverIDTag(serverID string) string { return "x-spire-server-id:" + serverID }
func spireKeyIDTag(keyID string) string   { return "x-spire-key-id:" + keyID }
func spireKeyTypeTag(kt keymanagerv1.KeyType) string {
	switch kt {
	case keymanagerv1.KeyType_EC_P256:
		return "x-spire-key-type:EC_P256"
	case keymanagerv1.KeyType_EC_P384:
		return "x-spire-key-type:EC_P384"
	case keymanagerv1.KeyType_RSA_2048:
		return "x-spire-key-type:RSA_2048"
	case keymanagerv1.KeyType_RSA_4096:
		return "x-spire-key-type:RSA_4096"
	default:
		return "x-spire-key-type:unknown"
	}
}

// fingerprint returns a SHA-256 hex fingerprint of DER-encoded public key bytes.
func fingerprint(pkixData []byte) string {
	sum := sha256.Sum256(pkixData)
	return hex.EncodeToString(sum[:])
}
