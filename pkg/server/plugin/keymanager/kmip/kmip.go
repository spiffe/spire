// Package kmip implements a SPIRE KeyManager plugin that stores and uses signing
// keys via a generic KMIP 2.1-compliant server (binary TTLV over TCP/TLS).
//
// Key metadata (server ID, SPIRE key ID, key type) is stored as standard KMIP
// Name attributes on each key object, so the plugin works with any spec-compliant
// KMIP server — no vendor extensions required.
package kmip

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	ovh "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/payloads"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const pluginName = "kmip"

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
	// KMIPAddr is the TCP address of the KMIP server (e.g. "kmip.example.com:5696").
	KMIPAddr string `hcl:"kmip_addr"`
	// CACertPath is the PEM-encoded CA certificate(s) used to verify the KMIP server
	// TLS certificate. Accepts either inline PEM content or a path to a PEM file.
	// Optional; when empty the system certificate pool is used.
	CACertPath string `hcl:"ca_cert_path"`
	// ClientCertPath is the PEM file of the mTLS client certificate.
	ClientCertPath string `hcl:"client_cert_path"`
	// ClientKeyPath is the PEM file of the mTLS client private key.
	ClientKeyPath string `hcl:"client_key_path"`
	// InsecureSkipVerify disables TLS certificate verification (test environments only).
	InsecureSkipVerify bool `hcl:"insecure_skip_verify"`
	// ServerID is a stable identifier for this SPIRE server instance.
	// All keys created by this plugin are tagged with a "spire-server-id:<ServerID>" Name
	// attribute so they can be recovered on restart via Locate.
	ServerID string `hcl:"server_id"`
}

// keyEntry maps a SPIRE key ID to the KMIP private key UID and the cached public key.
type keyEntry struct {
	privateKeyUID string
	publicKey     *keymanagerv1.PublicKey
}

// Plugin implements the SPIRE KeyManager using a generic KMIP server.
type Plugin struct {
	keymanagerv1.UnsafeKeyManagerServer
	configv1.UnsafeConfigServer

	logger   hclog.Logger
	mu       sync.RWMutex
	entries  map[string]keyEntry // spireKeyID → keyEntry
	serverID string
	client   *kmipclient.Client
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

// Configure parses HCL config, dials the KMIP server, and recovers existing
// keys via Locate.
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

	p.mu.Lock()
	defer p.mu.Unlock()

	p.client = client
	p.serverID = cfg.ServerID
	p.entries = make(map[string]keyEntry)

	if err := p.recoverKeys(ctx); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to recover keys from KMIP server: %v", err)
	}

	p.logger.Info("KMIP KeyManager configured",
		"server_id", p.serverID,
		"keys_recovered", len(p.entries),
	)
	return &configv1.ConfigureResponse{}, nil
}

// Validate validates the plugin configuration without applying it.
func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)
	return &configv1.ValidateResponse{Valid: err == nil, Notes: notes}, nil
}

// GenerateKey creates a new asymmetric key pair in the KMIP server.
func (p *Plugin) GenerateKey(ctx context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.KeyType == keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE {
		return nil, status.Error(codes.InvalidArgument, "key type is required")
	}

	p.mu.RLock()
	client := p.client
	serverID := p.serverID
	p.mu.RUnlock()
	if client == nil {
		return nil, status.Error(codes.FailedPrecondition, "plugin not configured")
	}

	createResp, err := createKeyPairForType(ctx, client, req.KeyType)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create key pair: %v", err)
	}

	// Activate both keys so they can be used for Sign operations.
	// KMIP keys start in PreActive state; Sign requires Active state.
	for _, uid := range []string{createResp.PrivateKeyUniqueIdentifier, createResp.PublicKeyUniqueIdentifier} {
		if _, actErr := client.Activate(uid).ExecContext(ctx); actErr != nil {
			// Synchronously destroy both keys on activation failure so orphaned keys
			// are not leaked silently; log any destroy failure for visibility.
			if _, err := client.Destroy(createResp.PrivateKeyUniqueIdentifier).Exec(); err != nil {
				p.logger.Warn("Failed to destroy private key after activation failure", "uid", createResp.PrivateKeyUniqueIdentifier, "err", err)
			}
			if _, err := client.Destroy(createResp.PublicKeyUniqueIdentifier).Exec(); err != nil {
				p.logger.Warn("Failed to destroy public key after activation failure", "uid", createResp.PublicKeyUniqueIdentifier, "err", err)
			}
			return nil, status.Errorf(codes.Internal, "failed to activate key %s: %v", uid, actErr)
		}
	}

	// Tag both key objects with SPIRE metadata using standard KMIP Name attributes.
	// These names are used by recoverKeys on restart.
	nameAttrs := spireNameAttributes(serverID, req.KeyId, req.KeyType)
	for _, uid := range []string{createResp.PrivateKeyUniqueIdentifier, createResp.PublicKeyUniqueIdentifier} {
		for _, name := range nameAttrs {
			if _, addErr := client.AddAttribute(uid, ovh.AttributeNameName, name).ExecContext(ctx); addErr != nil {
				// Synchronously destroy both keys on tag failure so orphaned keys are
				// not leaked silently; log any destroy failure for visibility.
				if _, err := client.Destroy(createResp.PrivateKeyUniqueIdentifier).Exec(); err != nil {
					p.logger.Warn("Failed to destroy private key after tag failure", "uid", createResp.PrivateKeyUniqueIdentifier, "err", err)
				}
				if _, err := client.Destroy(createResp.PublicKeyUniqueIdentifier).Exec(); err != nil {
					p.logger.Warn("Failed to destroy public key after tag failure", "uid", createResp.PublicKeyUniqueIdentifier, "err", err)
				}
				return nil, status.Errorf(codes.Internal, "failed to tag key %s: %v", uid, addErr)
			}
		}
	}

	pkixData, err := getPublicKeyPKIX(ctx, client, createResp.PublicKeyUniqueIdentifier, req.KeyType)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve public key: %v", err)
	}

	pk := &keymanagerv1.PublicKey{
		Id:          req.KeyId,
		Type:        req.KeyType,
		PkixData:    pkixData,
		Fingerprint: fingerprint(pkixData),
	}

	p.mu.Lock()
	// Schedule async destruction of the previous key for this key ID if it exists.
	if old, ok := p.entries[req.KeyId]; ok {
		oldUID := old.privateKeyUID
		go func() {
			if _, err := client.Destroy(oldUID).Exec(); err != nil {
				p.logger.Warn("Failed to destroy old private key", "uid", oldUID, "err", err)
			}
		}()
	}
	p.entries[req.KeyId] = keyEntry{privateKeyUID: createResp.PrivateKeyUniqueIdentifier, publicKey: pk}
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

	params, err := toCryptographicParameters(entry.publicKey.Type, req.SignerOpts)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	signResp, err := client.Sign(entry.privateKeyUID).
		WithCryptographicParameters(params).
		DigestedData(req.Data).
		ExecContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to sign data: %v", err)
	}

	return &keymanagerv1.SignDataResponse{
		Signature:      signResp.SignatureData,
		KeyFingerprint: entry.publicKey.Fingerprint,
	}, nil
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

// GetPublicKeys returns all cached public keys.
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

// recoverKeys fetches all private keys tagged with this server's server-id Name
// and rebuilds the in-memory entries map. Must be called while p.mu is held.
func (p *Plugin) recoverKeys(ctx context.Context) error {
	locResp, err := p.client.Locate().
		WithAttribute(ovh.AttributeNameName, ovh.Name{
			NameValue: serverIDNameValue(p.serverID),
			NameType:  ovh.NameTypeUninterpretedTextString,
		}).
		ExecContext(ctx)
	if err != nil {
		return fmt.Errorf("locate keys for server %q: %w", p.serverID, err)
	}

	for _, privUID := range locResp.UniqueIdentifier {
		attrResp, err := p.client.GetAttributes(privUID, ovh.AttributeNameName).ExecContext(ctx)
		if err != nil {
			p.logger.Warn("Failed to get Name attributes during recovery", "uid", privUID, "err", err)
			continue
		}

		names := collectNameValues(attrResp.Attribute)
		spireKeyID := prefixValue(names, "spire-key-id:")
		if spireKeyID == "" {
			p.logger.Warn("Key missing spire-key-id name; skipping", "uid", privUID)
			continue
		}
		keyType, err := parseKeyTypeName(prefixValue(names, "spire-key-type:"))
		if err != nil {
			p.logger.Warn("Key has unrecognised spire-key-type; skipping", "uid", privUID, "err", err)
			continue
		}

		pubUID, err := getLinkedUID(ctx, p.client, privUID, ovh.LinkTypePublicKeyLink)
		if err != nil {
			p.logger.Warn("Failed to find linked public key during recovery", "uid", privUID, "err", err)
			continue
		}

		pkixData, err := getPublicKeyPKIX(ctx, p.client, pubUID, keyType)
		if err != nil {
			p.logger.Warn("Failed to retrieve public key during recovery", "pub_uid", pubUID, "err", err)
			continue
		}

		pk := &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    pkixData,
			Fingerprint: fingerprint(pkixData),
		}
		p.entries[spireKeyID] = keyEntry{privateKeyUID: privUID, publicKey: pk}
		p.logger.Debug("Recovered key", "spire_key_id", spireKeyID, "priv_uid", privUID)
	}
	return nil
}

// createKeyPairForType creates a key pair for the given SPIRE key type.
func createKeyPairForType(ctx context.Context, c *kmipclient.Client, kt keymanagerv1.KeyType) (*payloads.CreateKeyPairResponsePayload, error) {
	const (
		privUsage = ovh.CryptographicUsageSign | ovh.CryptographicUsageCertificateSign | ovh.CryptographicUsageCRLSign
		pubUsage  = ovh.CryptographicUsageVerify
	)
	switch kt {
	case keymanagerv1.KeyType_EC_P256:
		return c.CreateKeyPair().ECDSA(ovh.RecommendedCurveP_256, privUsage, pubUsage).ExecContext(ctx)
	case keymanagerv1.KeyType_EC_P384:
		return c.CreateKeyPair().ECDSA(ovh.RecommendedCurveP_384, privUsage, pubUsage).ExecContext(ctx)
	case keymanagerv1.KeyType_RSA_2048:
		return c.CreateKeyPair().RSA(2048, privUsage, pubUsage).ExecContext(ctx)
	case keymanagerv1.KeyType_RSA_4096:
		return c.CreateKeyPair().RSA(4096, privUsage, pubUsage).ExecContext(ctx)
	default:
		return nil, fmt.Errorf("unsupported key type: %v", kt)
	}
}

// getPublicKeyPKIX fetches a public key from the KMIP server and returns
// DER-encoded SubjectPublicKeyInfo (PKIX) bytes.
//
// It explicitly requests the transparent key format to avoid servers that fail
// when trying to export as X.509/SPKI by default (e.g. Eviden KMS binary TTLV).
// After retrieving the transparent key, it converts to PKIX using the OVH library.
func getPublicKeyPKIX(ctx context.Context, c *kmipclient.Client, pubUID string, kt keymanagerv1.KeyType) ([]byte, error) {
	// Request the transparent format explicitly. Some servers (including Eviden KMS
	// over binary TTLV) fail when attempting to return X.509/SPKI as their default.
	var reqFormat ovh.KeyFormatType
	if isRSA(kt) {
		reqFormat = ovh.KeyFormatTypeTransparentRSAPublicKey
	} else {
		reqFormat = ovh.KeyFormatTypeTransparentECPublicKey
	}

	getResp, err := c.Get(pubUID).WithKeyFormat(reqFormat).ExecContext(ctx)
	if err != nil {
		// Fallback: try without a format hint (for servers that don't support transparent format).
		getResp, err = c.Get(pubUID).ExecContext(ctx)
		if err != nil {
			return nil, fmt.Errorf("get public key %s: %w", pubUID, err)
		}
	}

	pk, ok := getResp.Object.(*ovh.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected PublicKey object for UID %s, got %T", pubUID, getResp.Object)
	}
	if pk.KeyBlock.KeyValue == nil {
		return nil, fmt.Errorf("key %s has no key value", pubUID)
	}
	// Wrapped (ByteString) — could be X.509 SPKI or PKCS#1.
	if pk.KeyBlock.KeyValue.Wrapped != nil {
		raw := *pk.KeyBlock.KeyValue.Wrapped
		if _, parseErr := x509.ParsePKIXPublicKey(raw); parseErr == nil {
			return raw, nil
		}
		if rsaKey, parseErr := x509.ParsePKCS1PublicKey(raw); parseErr == nil {
			return x509.MarshalPKIXPublicKey(rsaKey)
		}
		return nil, fmt.Errorf("wrapped key material for %s is not a recognised public key format", pubUID)
	}
	// Transparent key — the OVH library parses curve/key material.
	if ecKey, ecErr := pk.ECDSA(); ecErr == nil {
		return x509.MarshalPKIXPublicKey(ecKey)
	}
	if rsaKey, rsaErr := pk.RSA(); rsaErr == nil {
		return x509.MarshalPKIXPublicKey(rsaKey)
	}
	return nil, fmt.Errorf("cannot extract public key from UID %s: unsupported format %v", pubUID, pk.KeyBlock.KeyFormatType)
}

// getLinkedUID retrieves the UniqueIdentifier of an object linked to uid via linkType.
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

// toCryptographicParameters maps a SPIRE SignerOpts to OVH CryptographicParameters.
func toCryptographicParameters(kt keymanagerv1.KeyType, opts any) (ovh.CryptographicParameters, error) {
	switch o := opts.(type) {
	case *keymanagerv1.SignDataRequest_HashAlgorithm:
		hashAlgo, err := toHashAlgorithm(o.HashAlgorithm)
		if err != nil {
			return ovh.CryptographicParameters{}, err
		}
		var sigAlgo ovh.DigitalSignatureAlgorithm
		switch o.HashAlgorithm {
		case keymanagerv1.HashAlgorithm_SHA256:
			if isRSA(kt) {
				sigAlgo = ovh.DigitalSignatureAlgorithmSHA_256WithRSAEncryption
			} else {
				sigAlgo = ovh.DigitalSignatureAlgorithmECDSAWithSHA256
			}
		case keymanagerv1.HashAlgorithm_SHA384:
			if isRSA(kt) {
				sigAlgo = ovh.DigitalSignatureAlgorithmSHA_384WithRSAEncryption
			} else {
				sigAlgo = ovh.DigitalSignatureAlgorithmECDSAWithSHA384
			}
		case keymanagerv1.HashAlgorithm_SHA512:
			if isRSA(kt) {
				sigAlgo = ovh.DigitalSignatureAlgorithmSHA_512WithRSAEncryption
			} else {
				sigAlgo = ovh.DigitalSignatureAlgorithmECDSAWithSHA512
			}
		default:
			return ovh.CryptographicParameters{}, fmt.Errorf("unsupported hash algorithm for signing: %v", o.HashAlgorithm)
		}
		return ovh.CryptographicParameters{
			HashingAlgorithm:          hashAlgo,
			DigitalSignatureAlgorithm: sigAlgo,
		}, nil
	case *keymanagerv1.SignDataRequest_PssOptions:
		hashAlgo, err := toHashAlgorithm(o.PssOptions.HashAlgorithm)
		if err != nil {
			return ovh.CryptographicParameters{}, err
		}
		return ovh.CryptographicParameters{
			HashingAlgorithm:          hashAlgo,
			DigitalSignatureAlgorithm: ovh.DigitalSignatureAlgorithmRSASSA_PSS,
		}, nil
	default:
		return ovh.CryptographicParameters{}, fmt.Errorf("unsupported signer opts type %T", opts)
	}
}

func toHashAlgorithm(h keymanagerv1.HashAlgorithm) (ovh.HashingAlgorithm, error) {
	switch h {
	case keymanagerv1.HashAlgorithm_SHA256:
		return ovh.HashingAlgorithmSHA_256, nil
	case keymanagerv1.HashAlgorithm_SHA384:
		return ovh.HashingAlgorithmSHA_384, nil
	case keymanagerv1.HashAlgorithm_SHA512:
		return ovh.HashingAlgorithmSHA_512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm: %v", h)
	}
}

func isRSA(kt keymanagerv1.KeyType) bool {
	return kt == keymanagerv1.KeyType_RSA_2048 || kt == keymanagerv1.KeyType_RSA_4096
}

// ── SPIRE Name attribute helpers ─────────────────────────────────────────────

const (
	prefixServerID = "spire-server-id:"
	prefixKeyID    = "spire-key-id:"
	prefixKeyType  = "spire-key-type:"
)

// spireNameAttributes returns the three Name attributes to attach to each key.
func spireNameAttributes(serverID, keyID string, kt keymanagerv1.KeyType) []ovh.Name {
	return []ovh.Name{
		{NameValue: serverIDNameValue(serverID), NameType: ovh.NameTypeUninterpretedTextString},
		{NameValue: prefixKeyID + keyID, NameType: ovh.NameTypeUninterpretedTextString},
		{NameValue: prefixKeyType + keyTypeName(kt), NameType: ovh.NameTypeUninterpretedTextString},
	}
}

func serverIDNameValue(id string) string { return prefixServerID + id }

func keyTypeName(kt keymanagerv1.KeyType) string {
	switch kt {
	case keymanagerv1.KeyType_EC_P256:
		return "EC_P256"
	case keymanagerv1.KeyType_EC_P384:
		return "EC_P384"
	case keymanagerv1.KeyType_RSA_2048:
		return "RSA_2048"
	case keymanagerv1.KeyType_RSA_4096:
		return "RSA_4096"
	default:
		return "unknown"
	}
}

// collectNameValues extracts all NameValue strings from a slice of KMIP Attributes.
func collectNameValues(attrs []ovh.Attribute) []string {
	out := make([]string, 0, len(attrs))
	for _, a := range attrs {
		if a.AttributeName != ovh.AttributeNameName {
			continue
		}
		if n, ok := a.AttributeValue.(ovh.Name); ok {
			out = append(out, n.NameValue)
		}
	}
	return out
}

// prefixValue finds the first name value that starts with the given prefix
// and returns the part after the prefix.
func prefixValue(names []string, prefix string) string {
	for _, n := range names {
		if strings.HasPrefix(n, prefix) {
			return n[len(prefix):]
		}
	}
	return ""
}

func parseKeyTypeName(s string) (keymanagerv1.KeyType, error) {
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
		return keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE, fmt.Errorf("unknown key type %q", s)
	}
}

// fingerprint returns a SHA-256 hex fingerprint of DER-encoded public key bytes.
func fingerprint(pkixData []byte) string {
	sum := sha256.Sum256(pkixData)
	return hex.EncodeToString(sum[:])
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
	if cfg.ServerID == "" {
		s.ReportError("server_id is required")
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
			pool, err := loadCACertPool(cfg.CACertPath)
			if err != nil {
				return nil, err
			}
			tlsCfg.RootCAs = pool
		}
		opts = append(opts, kmipclient.WithTlsConfig(tlsCfg))
	}

	if cfg.ClientCertPath != "" && cfg.ClientKeyPath != "" {
		opts = append(opts, kmipclient.WithClientCertFiles(cfg.ClientCertPath, cfg.ClientKeyPath))
	}

	return kmipclient.Dial(cfg.KMIPAddr, opts...)
}

// loadCACertPool loads one or more CA certificates from either a file path or
// inline PEM content (detected by the presence of a PEM "BEGIN" block), matching
// the value-or-file behaviour of other SPIRE plugins.
func loadCACertPool(caCert string) (*x509.CertPool, error) {
	var pemBytes []byte
	if strings.Contains(caCert, "-----BEGIN") {
		pemBytes = []byte(caCert)
	} else {
		var err error
		pemBytes, err = os.ReadFile(caCert)
		if err != nil {
			return nil, fmt.Errorf("read CA cert %s: %w", caCert, err)
		}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("no valid certificates found in %s", caCert)
	}
	return pool, nil
}
