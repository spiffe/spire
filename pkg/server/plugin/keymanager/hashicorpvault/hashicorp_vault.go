package hashicorpvault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/andres-erbsen/clock"
	"github.com/gofrs/uuid/v5"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"os"
	"sync"
	"time"
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
	KeyName   string
	PublicKey *keymanagerv1.PublicKey
}

type pluginHooks struct {
	clk clock.Clock
	// Used for testing only.
	lookupEnv            func(string) (string, bool)
	scheduleDeleteSignal chan error
}

// Config provides configuration context for the plugin.
type Config struct {
	// A URL of Vault server. (e.g., https://vault.example.com:8443/)
	VaultAddr string `hcl:"vault_addr" json:"vault_addr"`
	// Name of the Vault namespace
	Namespace string `hcl:"namespace" json:"namespace"`
	// TransitEnginePath specifies the path to the transit engine to perform key operations.
	TransitEnginePath string `hcl:"transit_engine_path" json:"transit_engine_path"`

	KeyIdentifierFile  string `hcl:"key_identifier_file" json:"key_identifier_file"`
	KeyIdentifierValue string `hcl:"key_identifier_value" json:"key_identifier_value"`

	// If true, vault client accepts any server certificates.
	// It should be used only test environment so on.
	InsecureSkipVerify bool `hcl:"insecure_skip_verify" json:"insecure_skip_verify"`
	// Path to a CA certificate file that the client verifies the server certificate.
	// Only PEM format is supported.
	CACertPath string `hcl:"ca_cert_path" json:"ca_cert_path"`

	// Configuration for the Token authentication method
	TokenAuth *TokenAuthConfig `hcl:"token_auth" json:"token_auth,omitempty"`
	// Configuration for the AppRole authentication method
	AppRoleAuth *AppRoleAuthConfig `hcl:"approle_auth" json:"approle_auth,omitempty"`
	// Configuration for the Client Certificate authentication method
	CertAuth *CertAuthConfig `hcl:"cert_auth" json:"cert_auth,omitempty"`
	// Configuration for the Kubernetes authentication method
	K8sAuth *K8sAuthConfig `hcl:"k8s_auth" json:"k8s_auth,omitempty"`
}

// TokenAuthConfig represents parameters for token auth method
type TokenAuthConfig struct {
	// Token string to set into "X-Vault-Token" header
	Token string `hcl:"token" json:"token"`
}

// AppRoleAuthConfig represents parameters for AppRole auth method.
type AppRoleAuthConfig struct {
	// Name of the mount point where AppRole auth method is mounted. (e.g., /auth/<mount_point>/login)
	// If the value is empty, use default mount point (/auth/approle)
	AppRoleMountPoint string `hcl:"approle_auth_mount_point" json:"approle_auth_mount_point"`
	// An identifier that selects the AppRole
	RoleID string `hcl:"approle_id" json:"approle_id"`
	// A credential that is required for login.
	SecretID string `hcl:"approle_secret_id" json:"approle_secret_id"`
}

// CertAuthConfig represents parameters for cert auth method
type CertAuthConfig struct {
	// Name of the mount point where Client Certificate Auth method is mounted. (e.g., /auth/<mount_point>/login)
	// If the value is empty, use default mount point (/auth/cert)
	CertAuthMountPoint string `hcl:"cert_auth_mount_point" json:"cert_auth_mount_point"`
	// Name of the Vault role.
	// If given, the plugin authenticates against only the named role.
	CertAuthRoleName string `hcl:"cert_auth_role_name" json:"cert_auth_role_name"`
	// Path to a client certificate file.
	// Only PEM format is supported.
	ClientCertPath string `hcl:"client_cert_path" json:"client_cert_path"`
	// Path to a client private key file.
	// Only PEM format is supported.
	ClientKeyPath string `hcl:"client_key_path" json:"client_key_path"`
}

// K8sAuthConfig represents parameters for Kubernetes auth method.
type K8sAuthConfig struct {
	// Name of the mount point where Kubernetes auth method is mounted. (e.g., /auth/<mount_point>/login)
	// If the value is empty, use default mount point (/auth/kubernetes)
	K8sAuthMountPoint string `hcl:"k8s_auth_mount_point" json:"k8s_auth_mount_point"`
	// Name of the Vault role.
	// The plugin authenticates against the named role.
	K8sAuthRoleName string `hcl:"k8s_auth_role_name" json:"k8s_auth_role_name"`
	// Path to the Kubernetes Service Account Token to use authentication with the Vault.
	TokenPath string `hcl:"token_path" json:"token_path"`
}

// Plugin is the main representation of this keymanager plugin
type Plugin struct {
	keymanagerv1.UnsafeKeyManagerServer
	configv1.UnsafeConfigServer

	logger     hclog.Logger
	serverID   string
	mu         sync.RWMutex
	entries    map[string]keyEntry
	entriesMtx sync.RWMutex

	authMethod AuthMethod
	cc         *ClientConfig
	vc         *Client

	scheduleDelete chan string
	cancelTasks    context.CancelFunc

	hooks pluginHooks
}

// New returns an instantiated plugin.
func New() *Plugin {
	return newPlugin()
}

// newPlugin returns a new plugin instance.
func newPlugin() *Plugin {
	return &Plugin{
		entries: make(map[string]keyEntry),
		hooks: pluginHooks{
			lookupEnv: os.LookupEnv,
			clk:       clock.New(),
		},
		scheduleDelete: make(chan string, 120),
	}
}

// SetLogger sets a logger
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.logger = log
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(Config)

	if err := hcl.Decode(&config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	serverID := config.KeyIdentifierValue
	if serverID == "" {
		var err error

		if serverID, err = getOrCreateServerID(config.KeyIdentifierFile); err != nil {
			return nil, err
		}
	}

	p.logger.Debug("Loaded server id", "server_id", serverID)

	if config.InsecureSkipVerify {
		p.logger.Warn("TLS verification of Vault certificates is skipped. This is only recommended for test environments.")
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
	p.serverID = serverID

	if p.vc == nil {
		err := p.genVaultClient()
		if err != nil {
			return nil, err
		}
	}

	p.logger.Debug("Fetching keys from Vault")
	keyEntries, err := p.vc.GetKeys(ctx)
	if err != nil {
		return nil, err
	}

	p.setCache(keyEntries)

	// Cancel previous tasks in case of re-configure.
	if p.cancelTasks != nil {
		p.cancelTasks()
	}

	// start tasks
	ctx, p.cancelTasks = context.WithCancel(context.Background())
	go p.scheduleDeleteTask(ctx)

	return &configv1.ConfigureResponse{}, nil
}

func parseAuthMethod(config *Config) (AuthMethod, error) {
	var authMethod AuthMethod
	if config.TokenAuth != nil {
		authMethod = TOKEN
	}

	if config.AppRoleAuth != nil {
		if err := checkForAuthMethodConfigured(authMethod); err != nil {
			return 0, err
		}
		authMethod = APPROLE
	}

	if config.CertAuth != nil {
		if err := checkForAuthMethodConfigured(authMethod); err != nil {
			return 0, err
		}
		authMethod = CERT
	}

	if config.K8sAuth != nil {
		if err := checkForAuthMethodConfigured(authMethod); err != nil {
			return 0, err
		}
		authMethod = K8S
	}

	if authMethod != 0 {
		return authMethod, nil
	}

	return 0, status.Error(codes.InvalidArgument, "one of the available authentication methods must be configured: 'Token, AppRole'")
}

func checkForAuthMethodConfigured(authMethod AuthMethod) error {
	if authMethod != 0 {
		return status.Error(codes.InvalidArgument, "only one authentication method can be configured")
	}
	return nil
}

func (p *Plugin) genClientParams(method AuthMethod, config *Config) (*ClientParams, error) {
	cp := &ClientParams{
		VaultAddr:         p.getEnvOrDefault(envVaultAddr, config.VaultAddr),
		Namespace:         p.getEnvOrDefault(envVaultNamespace, config.Namespace),
		TransitEnginePath: p.getEnvOrDefault(envVaultTransitEnginePath, config.TransitEnginePath),
		CACertPath:        p.getEnvOrDefault(envVaultCACert, config.CACertPath),
		TLSSKipVerify:     config.InsecureSkipVerify,
	}

	switch method {
	case TOKEN:
		cp.Token = p.getEnvOrDefault(envVaultToken, config.TokenAuth.Token)
	case APPROLE:
		cp.AppRoleAuthMountPoint = config.AppRoleAuth.AppRoleMountPoint
		cp.AppRoleID = p.getEnvOrDefault(envVaultAppRoleID, config.AppRoleAuth.RoleID)
		cp.AppRoleSecretID = p.getEnvOrDefault(envVaultAppRoleSecretID, config.AppRoleAuth.SecretID)
	case CERT:
		cp.CertAuthMountPoint = config.CertAuth.CertAuthMountPoint
		cp.CertAuthRoleName = config.CertAuth.CertAuthRoleName
		cp.ClientCertPath = p.getEnvOrDefault(envVaultClientCert, config.CertAuth.ClientCertPath)
		cp.ClientKeyPath = p.getEnvOrDefault(envVaultClientKey, config.CertAuth.ClientKeyPath)
	case K8S:
		if config.K8sAuth.K8sAuthRoleName == "" {
			return nil, status.Error(codes.InvalidArgument, "k8s_auth_role_name is required")
		}
		if config.K8sAuth.TokenPath == "" {
			return nil, status.Error(codes.InvalidArgument, "token_path is required")
		}
		cp.K8sAuthMountPoint = config.K8sAuth.K8sAuthMountPoint
		cp.K8sAuthRoleName = config.K8sAuth.K8sAuthRoleName
		cp.K8sAuthTokenPath = config.K8sAuth.TokenPath
	}

	return cp, nil
}

func (p *Plugin) getEnvOrDefault(envKey, fallback string) string {
	if value, ok := p.hooks.lookupEnv(envKey); ok {
		return value
	}
	return fallback
}

// scheduleDeleteTask is a long-running task that deletes keys that are stale
func (p *Plugin) scheduleDeleteTask(ctx context.Context) {
	backoffMin := 1 * time.Second
	backoffMax := 60 * time.Second
	backoff := backoffMin

	for {
		select {
		case <-ctx.Done():
			return
		case keyID := <-p.scheduleDelete:
			log := p.logger.With("key_id", keyID)

			if p.vc == nil {
				err := p.genVaultClient()
				if err != nil {
					log.Error("Failed to generate vault client", "reason", err)
					p.notifyDelete(err)
					// TODO: Should we re-enqueue here?
				}
			}

			err := p.vc.DeleteKey(ctx, keyID)

			if err == nil {
				log.Debug("Key deleted")
				backoff = backoffMin
				p.notifyDelete(nil)
				continue
			}

			// For any other error, log it and re-enqueue the key for deletion as it might be a recoverable error
			log.Error("It was not possible to schedule key for deletion. Trying to re-enqueue it for deletion", "reason", err)

			select {
			case p.scheduleDelete <- keyID:
				log.Debug("Key re-enqueued for deletion")
			default:
				log.Error("Failed to re-enqueue key for deletion")
			}

			p.notifyDelete(nil)
			backoff = min(backoff*2, backoffMax)
			p.hooks.clk.Sleep(backoff)
		}
	}
}

// Used for testing only
func (p *Plugin) notifyDelete(err error) {
	if p.hooks.scheduleDeleteSignal != nil {
		p.hooks.scheduleDeleteSignal <- err
	}
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

	if keyEntry, ok := p.getKeyEntry(spireKeyID); ok {
		select {
		case p.scheduleDelete <- keyEntry.KeyName:
			p.logger.Debug("Key enqueued for deletion", "key_name", keyEntry.KeyName)
		default:
			p.logger.Error("Failed to enqueue key for deletion", "key_name", keyEntry.KeyName)
		}
	}

	p.setKeyEntry(spireKeyID, *newKeyEntry)

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

	signature, err := p.vc.SignData(ctx, keyEntry.KeyName, req.Data, hashAlgo, signingAlgo)
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
	var keys = make([]*keymanagerv1.PublicKey, 0, len(p.entries))

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

	keyName, err := p.generateKeyName(spireKeyID)
	if err != nil {
		return nil, err
	}

	err = p.vc.CreateKey(ctx, keyName, *kt)
	if err != nil {
		return nil, err
	}

	return p.vc.getKeyEntry(ctx, keyName)
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
	vc, err := p.cc.NewAuthenticatedClient(p.authMethod, renewCh)
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

func (p *Plugin) setCache(keyEntries []*keyEntry) {
	// clean previous cache
	p.entriesMtx.Lock()
	defer p.entriesMtx.Unlock()
	p.entries = make(map[string]keyEntry)

	// add results to cache
	for _, e := range keyEntries {
		p.entries[e.PublicKey.Id] = *e
		p.logger.Debug("Key loaded", "key_id", e.PublicKey.Id, "key_type", e.PublicKey.Type)
	}
}

// setKeyEntry adds the entry to the cache that matches the provided SPIRE Key ID
func (p *Plugin) setKeyEntry(keyID string, ke keyEntry) {
	p.entriesMtx.Lock()
	defer p.entriesMtx.Unlock()

	p.entries[keyID] = ke
}

// getKeyEntry gets the entry from the cache that matches the provided SPIRE Key ID
func (p *Plugin) getKeyEntry(keyID string) (ke keyEntry, ok bool) {
	p.entriesMtx.RLock()
	defer p.entriesMtx.RUnlock()

	ke, ok = p.entries[keyID]
	return ke, ok
}

// generateKeyName returns a new identifier to be used as a key name.
// The returned name has the form: <UUID>-<SPIRE-KEY-ID>
// where UUID is a new randomly generated UUID and SPIRE-KEY-ID is provided
// through the spireKeyID parameter.
func (p *Plugin) generateKeyName(spireKeyID string) (keyName string, err error) {
	uniqueID, err := generateUniqueID()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s-%s", uniqueID, spireKeyID), nil
}

// generateUniqueID returns a randomly generated UUID.
func generateUniqueID() (id string, err error) {
	u, err := uuid.NewV4()
	if err != nil {
		return "", status.Errorf(codes.Internal, "could not create a randomly generated UUID: %v", err)
	}

	return u.String(), nil
}

func getOrCreateServerID(idPath string) (string, error) {
	data, err := os.ReadFile(idPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return createServerID(idPath)
	case err != nil:
		return "", status.Errorf(codes.Internal, "failed to read server ID from path: %v", err)
	}

	serverID, err := uuid.FromString(string(data))
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to parse server ID from path: %v", err)
	}
	return serverID.String(), nil
}

// createServerID creates a randomly generated UUID to be used as a server ID
// and stores it in the specified idPath.
func createServerID(idPath string) (string, error) {
	id, err := generateUniqueID()
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to generate ID for server: %v", err)
	}

	err = diskutil.WritePrivateFile(idPath, []byte(id))
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to persist server ID on path: %v", err)
	}

	return id, nil
}
