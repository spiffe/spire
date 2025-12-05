package azurekeyvault

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/andres-erbsen/clock"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName              = "azure_key_vault"
	keyNamePrefix           = "spire-agent-key"
	tagNameAgentID          = "spire-agent-id"
	tagNameAgentTrustDomain = "spire-agent-td"
	minimumKeyTTL           = time.Hour * 24 * 30 // 1 month
	defaultKeyTTL           = time.Hour * 24 * 14 // 2 weeks
	keyNameTag              = "key_name"
	reasonTag               = "reason"
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
	KeyID      string
	KeyName    string
	keyVersion string
	PublicKey  *keymanagerv1.PublicKey
}

type pluginHooks struct {
	newKeyVaultClient func(creds azcore.TokenCredential, keyVaultURI string) (cloudKeyManagementService, error)
	fetchCredential   func() (azcore.TokenCredential, error)
	clk               clock.Clock
	// Used for testing only.
	scheduleDeleteSignal chan error
	refreshKeysSignal    chan error
}

// Config provides configuration context for the plugin.
type Config struct {
	KeyIdentifierValue string `hcl:"key_identifier_value" json:"key_identifier_value"`
	KeyVaultURI        string `hcl:"key_vault_uri" json:"key_vault_uri"`
	AgentIDEnvVar      string `hcl:"agent_id_env_var" json:"agent_id_env_var"`
	KeyTTL             string `hcl:"key_ttl" json:"key_ttl"`
	TenantID           string `hcl:"tenant_id" json:"tenant_id"`
	SubscriptionID     string `hcl:"subscription_id" json:"subscription_id"`
	AppID              string `hcl:"app_id" json:"app_id"`
	AppSecret          string `hcl:"app_secret" json:"app_secret"`
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *Config {
	newConfig := new(Config)

	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	if newConfig.KeyVaultURI == "" {
		status.ReportError("configuration is missing the Key Vault URI")
	}

	if newConfig.AgentIDEnvVar == "" {
		status.ReportError("configuration requires agent_id_env_var")
	}

	if newConfig.KeyIdentifierValue == "" {
		status.ReportError("configuration requires key_identifier_value")
	}

	if len(newConfig.KeyIdentifierValue) > 256 {
		status.ReportError("Key identifier must not be longer than 256 characters")
	}

	// Parse key_ttl, default to 2 weeks if not specified
	if newConfig.KeyTTL == "" {
		newConfig.KeyTTL = defaultKeyTTL.String()
	}

	return newConfig
}

// Plugin is the main representation of this keymanager plugin
type Plugin struct {
	keymanagerv1.UnsafeKeyManagerServer
	configv1.UnsafeConfigServer
	log            hclog.Logger
	mu             sync.RWMutex
	entries        map[string]keyEntry
	entriesMtx     sync.RWMutex
	keyVaultClient cloudKeyManagementService
	trustDomain    string
	agentID        string
	hooks          pluginHooks
	keyTags        map[string]*string
	keyTTL         time.Duration
	scheduleDelete chan string
	cancelTasks    context.CancelFunc
}

// New returns an instantiated plugin.
func New() *Plugin {
	return newPlugin(newKeyVaultClient)
}

// newPlugin returns a new plugin instance.
func newPlugin(
	newKeyVaultClient func(creds azcore.TokenCredential, keyVaultURI string) (cloudKeyManagementService, error),
) *Plugin {
	return &Plugin{
		entries: make(map[string]keyEntry),
		hooks: pluginHooks{
			newKeyVaultClient: newKeyVaultClient,
			clk:               clock.New(),
			fetchCredential: func() (azcore.TokenCredential, error) {
				return azidentity.NewDefaultAzureCredential(nil)
			},
		},
		scheduleDelete: make(chan string, 120),
	}
}

// SetLogger sets a logger
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	agentID, err := getAgentID(newConfig.KeyIdentifierValue, newConfig.AgentIDEnvVar)
	if err != nil {
		return nil, err
	}
	p.log.Debug("Loaded agent id", "agent_id", agentID)

	var client cloudKeyManagementService

	switch {
	case newConfig.SubscriptionID != "", newConfig.AppID != "", newConfig.AppSecret != "", newConfig.TenantID != "":
		if newConfig.TenantID == "" {
			return nil, status.Errorf(codes.InvalidArgument, "invalid configuration, missing tenant id")
		}
		if newConfig.SubscriptionID == "" {
			return nil, status.Errorf(codes.InvalidArgument, "invalid configuration, missing subscription id")
		}
		if newConfig.AppID == "" {
			return nil, status.Errorf(codes.InvalidArgument, "invalid configuration, missing application id")
		}
		if newConfig.AppSecret == "" {
			return nil, status.Errorf(codes.InvalidArgument, "invalid configuration, missing app secret")
		}

		creds, err := azidentity.NewClientSecretCredential(newConfig.TenantID, newConfig.AppID, newConfig.AppSecret, nil)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to get client credential: %v", err)
		}

		client, err = p.hooks.newKeyVaultClient(creds, newConfig.KeyVaultURI)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create Key Vault client with client credentials: %v", err)
		}
	default:
		cred, err := p.hooks.fetchCredential()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to fetch client credential: %v", err)
		}
		client, err = p.hooks.newKeyVaultClient(cred, newConfig.KeyVaultURI)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create Key Vault client with MSI credential: %v", err)
		}
	}

	// Parse key_ttl duration
	keyTTL, err := time.ParseDuration(newConfig.KeyTTL)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid key_ttl duration %q: %v", newConfig.KeyTTL, err)
	}

	fetcher := &keyFetcher{
		keyVaultClient: client,
		log:            p.log,
		agentID:        agentID,
		trustDomain:    req.CoreConfiguration.TrustDomain,
	}

	p.log.Debug("Fetching keys from Azure Key Vault", "key_vault_uri", newConfig.KeyVaultURI)
	keyEntries, err := fetcher.fetchKeyEntries(ctx)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.setCache(keyEntries)
	p.keyVaultClient = client
	p.trustDomain = req.CoreConfiguration.TrustDomain
	p.agentID = agentID
	p.keyTTL = keyTTL
	p.keyTags = make(map[string]*string)
	p.keyTags[tagNameAgentTrustDomain] = to.Ptr(req.CoreConfiguration.TrustDomain)
	p.keyTags[tagNameAgentID] = to.Ptr(agentID)

	// Cancel previous tasks in case of re-configure.
	if p.cancelTasks != nil {
		p.cancelTasks()
	}

	// Start background tasks
	var taskCtx context.Context
	taskCtx, p.cancelTasks = context.WithCancel(context.Background())
	go p.scheduleDeleteTask(taskCtx)
	go p.refreshKeysTask(taskCtx)

	// Run cleanup at startup (non-blocking)
	go p.cleanupStaleKeys(taskCtx)

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(ctx context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

// GenerateKey creates a key in Key Vault. If a key already exists in the local
// storage, it is updated.
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

	p.setKeyEntry(spireKeyID, *newKeyEntry)

	return &keymanagerv1.GenerateKeyResponse{
		PublicKey: newKeyEntry.PublicKey,
	}, nil
}

func (p *Plugin) createKey(ctx context.Context, spireKeyID string, keyType keymanagerv1.KeyType) (*keyEntry, error) {
	createKeyParameters, err := getCreateKeyParameters(keyType, p.keyTags)
	if err != nil {
		return nil, err
	}

	keyName, err := p.generateKeyName(spireKeyID)
	if err != nil {
		return nil, fmt.Errorf("could not generate key name: %w", err)
	}

	createResp, err := p.keyVaultClient.CreateKey(ctx, keyName, *createKeyParameters, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create key: %v", err)
	}
	log := p.log.With("key_id", *createResp.Key.KID)
	log.Debug("Key created", "algorithm", *createResp.Key.Kty)

	rawKey, err := keyVaultKeyToRawKey(createResp.Key)
	if err != nil {
		return nil, err
	}
	publicKey, err := x509.MarshalPKIXPublicKey(rawKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal public key: %v", err)
	}

	return &keyEntry{
		KeyID:      string(*createResp.Key.KID),
		KeyName:    createResp.Key.KID.Name(),
		keyVersion: createResp.Key.KID.Version(),
		PublicKey: &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    publicKey,
			Fingerprint: makeFingerprint(publicKey),
		},
	}, nil
}

// SignData creates a digital signature for the data to be signed
func (p *Plugin) SignData(ctx context.Context, req *keymanagerv1.SignDataRequest) (*keymanagerv1.SignDataResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.SignerOpts == nil {
		return nil, status.Error(codes.InvalidArgument, "signer opts is required")
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	key, hasKey := p.getKeyEntry(req.KeyId)
	if !hasKey {
		return nil, status.Errorf(codes.NotFound, "key %q not found", req.KeyId)
	}

	keyType := key.PublicKey.Type
	keyName := key.KeyName
	keyVersion := key.keyVersion
	keyFingerprint := key.PublicKey.Fingerprint

	signingAlgo, err := signingAlgorithmForKeyVault(keyType, req.SignerOpts)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	signResponse, err := p.keyVaultClient.Sign(ctx, keyName, keyVersion, azkeys.SignParameters{
		Algorithm: to.Ptr(signingAlgo),
		Value:     req.Data,
	}, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to sign: %v", err)
	}

	result := signResponse.Result
	signatureBytes, err := keyVaultSignatureToASN1Encoded(result, keyType)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to convert Key Vault signature to ASN.1/DER format: %v", err)
	}

	return &keymanagerv1.SignDataResponse{
		Signature:      signatureBytes,
		KeyFingerprint: keyFingerprint,
	}, nil
}

// GetPublicKey returns the public key for a given key
func (p *Plugin) GetPublicKey(_ context.Context, req *keymanagerv1.GetPublicKeyRequest) (*keymanagerv1.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}

	p.entriesMtx.RLock()
	defer p.entriesMtx.RUnlock()

	entry, ok := p.entries[req.KeyId]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "key %q not found", req.KeyId)
	}

	return &keymanagerv1.GetPublicKeyResponse{
		PublicKey: entry.PublicKey,
	}, nil
}

// GetPublicKeys return the publicKey for all the keys
func (p *Plugin) GetPublicKeys(context.Context, *keymanagerv1.GetPublicKeysRequest) (*keymanagerv1.GetPublicKeysResponse, error) {
	var keys []*keymanagerv1.PublicKey
	p.entriesMtx.RLock()
	defer p.entriesMtx.RUnlock()
	for _, key := range p.entries {
		keys = append(keys, key.PublicKey)
	}

	return &keymanagerv1.GetPublicKeysResponse{PublicKeys: keys}, nil
}

// getKeyEntry gets the entry from the cache that matches the provided SPIRE Key ID
func (p *Plugin) getKeyEntry(keyID string) (ke keyEntry, ok bool) {
	p.entriesMtx.RLock()
	defer p.entriesMtx.RUnlock()

	ke, ok = p.entries[keyID]
	return ke, ok
}

// setKeyEntry adds the entry to the cache that matches the provided SPIRE Key ID
func (p *Plugin) setKeyEntry(keyID string, ke keyEntry) {
	p.entriesMtx.Lock()
	defer p.entriesMtx.Unlock()

	p.entries[keyID] = ke
}

func (p *Plugin) setCache(keyEntries []*keyEntry) {
	// clean previous cache
	p.entriesMtx.Lock()
	defer p.entriesMtx.Unlock()
	p.entries = make(map[string]keyEntry)

	// add results to cache
	for _, e := range keyEntries {
		p.entries[e.PublicKey.Id] = *e
		p.log.Debug("Key loaded", "key_id", e.KeyID, "key_name", e.KeyName)
	}
}

// generateKeyName returns a new identifier to be used as a key name.
// The returned name has the form: spire-agent-key-<AGENT-ID>-<SPIRE-KEY-ID>,
// where AGENT-ID is the unique agent identifier and SPIRE-KEY-ID is provided
// through the spireKeyID parameter.
func (p *Plugin) generateKeyName(spireKeyID string) (keyName string, err error) {
	if p.agentID == "" {
		return "", status.Errorf(codes.FailedPrecondition, "agent ID not configured")
	}

	return fmt.Sprintf("%s-%s-%s", keyNamePrefix, p.agentID, spireKeyID), nil
}

func getAgentID(keyIdentifierValue, envVarName string) (string, error) {
	envValue := os.Getenv(envVarName)
	if envValue == "" {
		return "", status.Errorf(codes.InvalidArgument, "environment variable %q is not set", envVarName)
	}

	agentID := fmt.Sprintf("%s-%s", keyIdentifierValue, envValue)
	if len(agentID) > 256 {
		return "", status.Errorf(codes.InvalidArgument, "agent ID exceeds maximum length of 256 characters")
	}

	return agentID, nil
}

func makeFingerprint(pkixData []byte) string {
	s := sha256.Sum256(pkixData)
	return hex.EncodeToString(s[:])
}

// refreshKeysTask will refresh the keys periodically.
// Refresh interval is key_ttl / 2 (e.g., if TTL is 336h, refresh every 168h).
// Keys will be updated with the same Operations they already have (Sign and Verify).
// The consequence of this is that the value of the field "Updated" in each key will be set to the current timestamp.
func (p *Plugin) refreshKeysTask(ctx context.Context) {
	// Refresh immediately at startup
	if err := p.refreshKeys(ctx); err != nil {
		p.log.Warn("Failed to refresh keys at startup", "error", err)
	}
	p.notifyRefreshKeys(nil)

	// Calculate refresh interval (50% of TTL)
	refreshInterval := p.keyTTL / 2
	if refreshInterval < time.Hour {
		refreshInterval = time.Hour // Minimum 1 hour
	}

	ticker := p.hooks.clk.Ticker(refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := p.refreshKeys(ctx)
			p.notifyRefreshKeys(err)
		}
	}
}

func (p *Plugin) notifyRefreshKeys(err error) {
	if p.hooks.refreshKeysSignal != nil {
		p.hooks.refreshKeysSignal <- err
	}
}

func (p *Plugin) refreshKeys(ctx context.Context) error {
	p.log.Debug("Refreshing keys")
	p.entriesMtx.Lock()
	defer p.entriesMtx.Unlock()
	var errs []string
	for _, entry := range p.entries {
		keyName := entry.KeyName
		keyVersion := entry.keyVersion
		_, err := p.keyVaultClient.GetKey(ctx, keyName, keyVersion, nil)
		if err != nil {
			p.log.Warn("failed fetching cached key to refresh it", keyNameTag, keyName)
			continue
		}

		// Update the key with the same key to only change the Updated timestamp
		_, err = p.keyVaultClient.UpdateKey(ctx, keyName, keyVersion, azkeys.UpdateKeyParameters{
			KeyOps: []*azkeys.JSONWebKeyOperation{to.Ptr(azkeys.JSONWebKeyOperationSign), to.Ptr(azkeys.JSONWebKeyOperationVerify)},
		}, nil)
		if err != nil {
			p.log.Error("Failed to refresh key", "key_id", entry.KeyID, reasonTag, err)
			errs = append(errs, err.Error())
		}
	}

	if errs != nil {
		return errors.New(strings.Join(errs, ": "))
	}
	return nil
}

// cleanupStaleKeys runs once at startup (non-blocking) to delete orphaned keys.
// It scans all keys tagged with spire-agent-td matching the trust domain and
// deletes keys where Updated timestamp is older than max(key_ttl, minimumKeyTTL).
func (p *Plugin) cleanupStaleKeys(ctx context.Context) {
	p.log.Debug("Cleaning up stale keys")
	pager := p.keyVaultClient.NewListKeysPager(nil)
	now := p.hooks.clk.Now()

	// Use max(key_ttl, minimumKeyTTL) to prevent single agent with short TTL from deleting all keys
	staleThreshold := p.keyTTL
	if staleThreshold < minimumKeyTTL {
		staleThreshold = minimumKeyTTL
	}
	maxStaleTime := now.Add(-staleThreshold)

	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			p.log.Error("Failed to list keys for cleanup", reasonTag, err)
			return
		}

		for _, key := range resp.Value {
			// Skip keys that do not belong to this trust domain
			trustDomain, hasTD := key.Tags[tagNameAgentTrustDomain]
			if !hasTD || *trustDomain != p.trustDomain {
				continue
			}

			// If the key has not been updated for staleThreshold, enqueue it for deletion
			updated := key.Attributes.Updated
			if updated.Before(maxStaleTime) {
				keyName := key.KID.Name()
				select {
				case p.scheduleDelete <- keyName:
					p.log.Debug("Stale key enqueued for deletion", keyNameTag, keyName)
				case <-ctx.Done():
					return
				default:
					p.log.Error("Failed to enqueue stale key for deletion", keyNameTag, keyName)
				}
			}
		}
	}
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
		case keyName := <-p.scheduleDelete:
			log := p.log.With(keyNameTag, keyName)

			_, err := p.keyVaultClient.DeleteKey(ctx, keyName, nil)
			if err == nil {
				log.Debug("Key deleted")
				backoff = backoffMin
				p.notifyDelete(nil)
				continue
			}

			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) {
				if respErr.StatusCode == http.StatusNotFound {
					log.Debug("Key already deleted", reasonTag, "No such key")
					p.notifyDelete(err)
					continue
				}
			}
			// For any other error, log it and re-enqueue the key for deletion as it might be a recoverable error
			log.Error("It was not possible to schedule key for deletion. Trying to re-enqueue it for deletion", reasonTag, err)

			select {
			case p.scheduleDelete <- keyName:
				log.Debug("Key re-enqueued for deletion")
			case <-ctx.Done():
				return
			default:
				log.Error("Failed to re-enqueue key for deletion")
			}
			p.notifyDelete(nil)
			backoff = min(backoff*2, backoffMax)
			p.hooks.clk.Sleep(backoff)
		}
	}
}

func (p *Plugin) notifyDelete(err error) {
	if p.hooks.scheduleDeleteSignal != nil {
		p.hooks.scheduleDeleteSignal <- err
	}
}
