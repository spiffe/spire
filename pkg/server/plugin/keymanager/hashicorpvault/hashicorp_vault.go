package hashicorpvault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"os"
	"sync"
)

const (
	pluginName = "hashicorp_vault"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		keymanagerv1.KeyManagerPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type keyEntry struct {
	PublicKey *keymanagerv1.PublicKey
}

type pluginHooks struct {
	// Used for testing only.
	scheduleDeleteSignal chan error
	refreshKeysSignal    chan error
	disposeKeysSignal    chan error

	newClient func(*ClientConfig, AuthMethod, chan struct{}) (client cloudKeyManagementService, err error)
	lookupEnv func(string) (string, bool)
}

// Config provides configuration context for the plugin.
type Config struct {
	// A URL of Vault server. (e.g., https://vault.example.com:8443/)
	VaultAddr string `hcl:"vault_addr" json:"vault_addr"`

	// Configuration for the Token authentication method
	TokenAuth *TokenAuthConfig `hcl:"token_auth" json:"token_auth,omitempty"`

	// TODO: Support other auth methods
	// TODO: Support client certificate and key
}

type TokenAuthConfig struct {
	// Token string to set into "X-Vault-Token" header
	Token string `hcl:"token" json:"token"`
}

// Plugin is the main representation of this keymanager plugin
type Plugin struct {
	keymanagerv1.UnsafeKeyManagerServer
	configv1.UnsafeConfigServer

	logger  hclog.Logger
	mu      sync.RWMutex
	entries map[string]keyEntry

	authMethod AuthMethod
	cc         *ClientConfig
	vc         cloudKeyManagementService

	hooks pluginHooks
}

// New returns an instantiated plugin.
func New() *Plugin {
	return newPlugin(func(config *ClientConfig, method AuthMethod, renewCh chan struct{}) (client cloudKeyManagementService, err error) {
		return config.NewAuthenticatedClient(method, renewCh)
	})
}

// newPlugin returns a new plugin instance.
func newPlugin(newClient func(*ClientConfig, AuthMethod, chan struct{}) (client cloudKeyManagementService, err error)) *Plugin {
	return &Plugin{
		entries: make(map[string]keyEntry),
		hooks: pluginHooks{
			lookupEnv: os.LookupEnv,
			newClient: newClient,
		},
	}
}

// SetLogger sets a logger
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.logger = log
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(Config)

	if err := hcl.Decode(&config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	am, err := parseAuthMethod(config)
	if err != nil {
		return nil, err
	}
	cp, err := p.genClientParams(am, config)
	if err != nil {
		return nil, err
	}
	vcConfig, err := NewClientConfig(cp, p.logger)
	if err != nil {
		return nil, err
	}

	p.authMethod = am
	p.cc = vcConfig

	return &configv1.ConfigureResponse{}, nil
}

func parseAuthMethod(config *Config) (AuthMethod, error) {
	var authMethod AuthMethod
	if config.TokenAuth != nil {
		authMethod = TOKEN
	}

	if authMethod != 0 {
		return authMethod, nil
	}

	return 0, status.Error(codes.InvalidArgument, "must be configured one of these authentication method 'Token'")
}

func (p *Plugin) genClientParams(method AuthMethod, config *Config) (*ClientParams, error) {
	cp := &ClientParams{
		VaultAddr: p.getEnvOrDefault(envVaultAddr, config.VaultAddr),
	}

	switch method {
	case TOKEN:
		cp.Token = p.getEnvOrDefault(envVaultToken, config.TokenAuth.Token)
	}

	return cp, nil
}

func (p *Plugin) getEnvOrDefault(envKey, fallback string) string {
	if value, ok := p.hooks.lookupEnv(envKey); ok {
		return value
	}
	return fallback
}

func (p *Plugin) GenerateKey(ctx context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.KeyType == keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE {
		return nil, status.Error(codes.InvalidArgument, "key type is required")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	spireKeyID := req.KeyId
	newKeyEntry, err := p.createKey(ctx, spireKeyID, req.KeyType)
	if err != nil {
		return nil, err
	}

	p.entries[spireKeyID] = *newKeyEntry

	return &keymanagerv1.GenerateKeyResponse{
		PublicKey: newKeyEntry.PublicKey,
	}, nil
}

func (p *Plugin) SignData(ctx context.Context, req *keymanagerv1.SignDataRequest) (*keymanagerv1.SignDataResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.SignerOpts == nil {
		return nil, status.Error(codes.InvalidArgument, "signer opts is required")
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	keyEntry, hasKey := p.entries[req.KeyId]
	if !hasKey {
		return nil, status.Errorf(codes.NotFound, "key %q not found", req.KeyId)
	}

	hashAlgo, signingAlgo, err := algosForKMS(keyEntry.PublicKey.Type, req.SignerOpts)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if p.vc == nil {
		err := p.genVaultClient()
		if err != nil {
			return nil, err
		}
	}

	signature, err := p.vc.SignData(ctx, req.KeyId, req.Data, hashAlgo, signingAlgo)
	if err != nil {
		return nil, err
	}

	return &keymanagerv1.SignDataResponse{
		Signature:      signature,
		KeyFingerprint: keyEntry.PublicKey.Fingerprint,
	}, nil
}

func (p *Plugin) GetPublicKey(_ context.Context, req *keymanagerv1.GetPublicKeyRequest) (*keymanagerv1.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.entries[req.KeyId]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "key %q not found", req.KeyId)
	}

	return &keymanagerv1.GetPublicKeyResponse{
		PublicKey: entry.PublicKey,
	}, nil
}

func (p *Plugin) GetPublicKeys(context.Context, *keymanagerv1.GetPublicKeysRequest) (*keymanagerv1.GetPublicKeysResponse, error) {
	var keys = make([]*keymanagerv1.PublicKey, len(p.entries), 0)

	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, key := range p.entries {
		keys = append(keys, key.PublicKey)
	}

	return &keymanagerv1.GetPublicKeysResponse{PublicKeys: keys}, nil
}

func algosForKMS(keyType keymanagerv1.KeyType, signerOpts any) (TransitHashAlgorithm, TransitSignatureAlgorithm, error) {
	var (
		hashAlgo keymanagerv1.HashAlgorithm
		isPSS    bool
	)

	switch opts := signerOpts.(type) {
	case *keymanagerv1.SignDataRequest_HashAlgorithm:
		hashAlgo = opts.HashAlgorithm
		isPSS = false
	case *keymanagerv1.SignDataRequest_PssOptions:
		if opts.PssOptions == nil {
			return "", "", errors.New("PSS options are required")
		}
		hashAlgo = opts.PssOptions.HashAlgorithm
		isPSS = true
		// opts.PssOptions.SaltLength is handled by Vault. The salt length matches the bits of the hashing algorithm.
	default:
		return "", "", fmt.Errorf("unsupported signer opts type %T", opts)
	}

	isRSA := keyType == keymanagerv1.KeyType_RSA_2048 || keyType == keymanagerv1.KeyType_RSA_4096

	switch {
	case hashAlgo == keymanagerv1.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM:
		return "", "", errors.New("hash algorithm is required")
	case keyType == keymanagerv1.KeyType_EC_P256 || keyType == keymanagerv1.KeyType_EC_P384:
		return TransitHashAlgorithmNone, TransitSignatureSignatureAlgorithmPKCS1v15, nil
	case isRSA && !isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA256:
		return TransitHashAlgorithmSHA256, TransitSignatureSignatureAlgorithmPKCS1v15, nil
	case isRSA && !isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA384:
		return TransitHashAlgorithmSHA384, TransitSignatureSignatureAlgorithmPKCS1v15, nil
	case isRSA && !isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA512:
		return TransitHashAlgorithmSHA512, TransitSignatureSignatureAlgorithmPKCS1v15, nil
	case isRSA && isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA256:
		return TransitHashAlgorithmSHA256, TransitSignatureSignatureAlgorithmPSS, nil
	case isRSA && isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA384:
		return TransitHashAlgorithmSHA384, TransitSignatureSignatureAlgorithmPSS, nil
	case isRSA && isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA512:
		return TransitHashAlgorithmSHA512, TransitSignatureSignatureAlgorithmPSS, nil
	default:
		return "", "", fmt.Errorf("unsupported combination of keytype: %v and hashing algorithm: %v", keyType, hashAlgo)
	}
}

func (p *Plugin) createKey(ctx context.Context, spireKeyID string, keyType keymanagerv1.KeyType) (*keyEntry, error) {
	if p.vc == nil {
		err := p.genVaultClient()
		if err != nil {
			return nil, err
		}
	}

	kt, err := convertToTransitKeyType(keyType)
	if err != nil {
		return nil, err
	}

	err = p.vc.CreateKey(ctx, spireKeyID, *kt)
	if err != nil {
		return nil, err
	}

	pk, err := p.vc.GetKey(ctx, spireKeyID)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode([]byte(pk))
	if pemBlock == nil || pemBlock.Type != "PUBLIC KEY" {
		return nil, status.Error(codes.Internal, "unable to decode PEM key")
	}

	return &keyEntry{
		PublicKey: &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    pemBlock.Bytes,
			Fingerprint: makeFingerprint(pemBlock.Bytes),
		},
	}, nil
}

func convertToTransitKeyType(keyType keymanagerv1.KeyType) (*TransitKeyType, error) {
	switch keyType {
	case keymanagerv1.KeyType_EC_P256:
		return to.Ptr(TransitKeyTypeECDSAP256), nil
	case keymanagerv1.KeyType_EC_P384:
		return to.Ptr(TransitKeyTypeECDSAP384), nil
	case keymanagerv1.KeyType_RSA_2048:
		return to.Ptr(TransitKeyTypeRSA2048), nil
	case keymanagerv1.KeyType_RSA_4096:
		return to.Ptr(TransitKeyTypeRSA4096), nil
	default:
		return nil, status.Errorf(codes.Internal, "unsupported key type: %v", keyType)
	}
}

func (p *Plugin) genVaultClient() error {
	renewCh := make(chan struct{})
	vc, err := p.hooks.newClient(p.cc, p.authMethod, renewCh)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to prepare authenticated client: %v", err)
	}
	p.vc = vc

	// if renewCh has been closed, the token can not be renewed and may expire,
	// it needs to re-authenticate to the Vault.
	go func() {
		<-renewCh
		p.mu.Lock()
		defer p.mu.Unlock()
		p.vc = nil
		p.logger.Debug("Going to re-authenticate to the Vault during the next key manager operation")
	}()

	return nil
}

func makeFingerprint(pkixData []byte) string {
	s := sha256.Sum256(pkixData)
	return hex.EncodeToString(s[:])
}
