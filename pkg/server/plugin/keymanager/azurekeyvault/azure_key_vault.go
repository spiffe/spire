package azurekeyvault

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/andres-erbsen/clock"
	"github.com/go-jose/go-jose/v4"
	"github.com/gofrs/uuid/v5"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName               = "azure_key_vault"
	refreshKeysFrequency     = time.Hour * 6
	algorithmTag             = "algorithm"
	keyIDTag                 = "key_id"
	keyNameTag               = "key_name"
	reasonTag                = "reason"
	disposeKeysFrequency     = time.Hour * 48
	maxStaleDuration         = time.Hour * 24 * 14 // Two weeks.
	keyNamePrefix            = "spire-key"
	tagNameServerID          = "spire-server-id"
	tagNameServerTrustDomain = "spire-server-td"
	tagNameKeyID             = "spire-key-id"
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
	newKeyVaultClient func(creds azcore.TokenCredential, keyVaultUri string) (cloudKeyManagementService, error)
	clk               clock.Clock
	fetchCredential   func() (azcore.TokenCredential, error)
	// Used for testing only.
	scheduleDeleteSignal chan error
	refreshKeysSignal    chan error
	disposeKeysSignal    chan error
}

// Config provides configuration context for the plugin.
type Config struct {
	KeyIdentifierFile  string `hcl:"key_identifier_file" json:"key_identifier_file"`
	KeyIdentifierValue string `hcl:"key_identifier_value" json:"key_identifier_value"`
	KeyVaultURI        string `hcl:"key_vault_uri" json:"key_vault_uri"`
	TenantID           string `hcl:"tenant_id" json:"tenant_id"`
	SubscriptionID     string `hcl:"subscription_id" json:"subscription_id"`
	AppID              string `hcl:"app_id" json:"app_id"`
	AppSecret          string `hcl:"app_secret" json:"app_secret"`

	// Shared keys configuration for multi-server deployments
	SharedKeys *SharedKeysConfig `hcl:"shared_keys" json:"shared_keys"`
}

type SharedKeysConfig struct {
	KeyNameTemplate string `hcl:"key_name_template" json:"key_name_template"`
	LockTagTemplate string `hcl:"lock_tag_template" json:"lock_tag_template"`
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

	if newConfig.SharedKeys != nil {
		if newConfig.SharedKeys.KeyNameTemplate == "" {
			status.ReportError("configuration missing key_name_template in shared_keys")
		} else {
			if _, err := template.New("key_name_template").Parse(newConfig.SharedKeys.KeyNameTemplate); err != nil {
				status.ReportErrorf("failed to parse key_name_template: %v", err)
			}
		}

		if newConfig.SharedKeys.LockTagTemplate == "" {
			status.ReportError("configuration missing lock_tag_template in shared_keys")
		} else {
			if _, err := template.New("lock_tag_template").Parse(newConfig.SharedKeys.LockTagTemplate); err != nil {
				status.ReportErrorf("failed to parse lock_tag_template: %v", err)
			}
		}
	} else {
		if newConfig.KeyIdentifierFile == "" && newConfig.KeyIdentifierValue == "" {
			status.ReportError("configuration requires a key identifier file or a key identifier value")
		}

		if newConfig.KeyIdentifierFile != "" && newConfig.KeyIdentifierValue != "" {
			status.ReportError("configuration can't have a key identifier file and a key identifier value at the same time")
		}

		if newConfig.KeyIdentifierValue != "" {
			if len(newConfig.KeyIdentifierValue) > 256 {
				status.ReportError("Key identifier must not be longer than 256 characters")
			}
		}
	}

	return newConfig
}

type pluginData struct {
	serverID          string
	trustDomain       string
	sharedKeysEnabled bool
	keyNameTemplate   *template.Template
	lockTagTemplate   *template.Template
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
	scheduleDelete chan string
	cancelTasks    context.CancelFunc
	hooks          pluginHooks
	keyTags        map[string]*string

	pd    *pluginData
	pdMtx sync.RWMutex
}

// New returns an instantiated plugin.
func New() *Plugin {
	return newPlugin(newKeyVaultClient)
}

// newPlugin returns a new plugin instance.
func newPlugin(
	newKeyVaultClient func(creds azcore.TokenCredential, keyVaultUri string) (cloudKeyManagementService, error),
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

	serverID := newConfig.KeyIdentifierValue
	if serverID == "" && newConfig.SharedKeys == nil {
		serverID, err = getOrCreateServerID(newConfig.KeyIdentifierFile)
		if err != nil {
			return nil, err
		}
	}
	if serverID != "" {
		p.log.Debug("Loaded server id", "server_id", serverID)
	}

	pd := &pluginData{
		serverID:    serverID,
		trustDomain: strings.ReplaceAll(req.CoreConfiguration.TrustDomain, ".", "-"),
	}

	var keyIDExtractor func(*azkeys.KeyItem) (string, bool)
	if newConfig.SharedKeys != nil {
		pd.sharedKeysEnabled = true
		pd.keyNameTemplate = template.Must(template.New("key_name_template").Parse(newConfig.SharedKeys.KeyNameTemplate))
		if newConfig.SharedKeys.LockTagTemplate != "" {
			pd.lockTagTemplate = template.Must(template.New("lock_tag_template").Parse(newConfig.SharedKeys.LockTagTemplate))
		}

		// In shared keys mode, extract KID from the tag
		keyIDExtractor = func(key *azkeys.KeyItem) (string, bool) {
			if key.Tags == nil {
				return "", false
			}
			kidTag, ok := key.Tags[tagNameKeyID]
			if !ok || kidTag == nil {
				return "", false
			}
			return *kidTag, true
		}
	} else {
		pd.sharedKeysEnabled = false
		keyIDExtractor = func(key *azkeys.KeyItem) (string, bool) {
			return spireKeyIDFromKeyName(key.KID.Name())
		}
	}

	p.setPluginData(pd)

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

	fetcher := &keyFetcher{
		keyVaultClient: client,
		log:            p.log,
		serverID:       serverID,
		trustDomain:    req.CoreConfiguration.TrustDomain,
		keyIDExtractor: keyIDExtractor,
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
	p.keyTags = make(map[string]*string)
	p.keyTags[tagNameServerTrustDomain] = to.Ptr(req.CoreConfiguration.TrustDomain)
	p.keyTags[tagNameServerID] = to.Ptr(serverID)

	// Cancel previous tasks in case of re-configure.
	if p.cancelTasks != nil {
		p.cancelTasks()
	}

	// start tasks
	ctx, p.cancelTasks = context.WithCancel(context.Background())
	go p.scheduleDeleteTask(ctx)
	go p.refreshKeysTask(ctx)
	go p.disposeKeysTask(ctx)

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(ctx context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

// refreshKeysTask will update the keys in the cache every 6 hours.
// Keys will be updated with the same Operations they already have (Sign and Verify).
// The consequence of this is that the value of the field "Updated" in each key belonging to the server will be set to the current timestamp.
// This is to be able to detect keys that are not in use by any server.
func (p *Plugin) refreshKeysTask(ctx context.Context) {
	ticker := p.hooks.clk.Ticker(refreshKeysFrequency)
	defer ticker.Stop()

	p.notifyRefreshKeys(nil)

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
			p.log.Error("Failed to refresh key", keyIDTag, entry.KeyID, reasonTag, err)
			errs = append(errs, err.Error())
		}
	}

	if errs != nil {
		return errors.New(strings.Join(errs, ": "))
	}
	return nil
}

// disposeKeysTask will be run every 48hs.
// It will delete keys that have an Updated timestamp value older than two weeks.
// It will only delete keys belonging to the current trust domain.
// disposeKeysTask relies on how the key trust domain tag (tagNameServerTrustDomain) is built to identity keys
// belonging to the current trust domain.
// Key trust domain tag example: `spire-server-td={TRUST_DOMAIN}`
func (p *Plugin) disposeKeysTask(ctx context.Context) {
	ticker := p.hooks.clk.Ticker(disposeKeysFrequency)
	defer ticker.Stop()

	p.notifyDisposeKeys(nil)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := p.disposeKeys(ctx)
			p.notifyDisposeKeys(err)
		}
	}
}

func (p *Plugin) notifyDisposeKeys(err error) {
	if p.hooks.disposeKeysSignal != nil {
		p.hooks.disposeKeysSignal <- err
	}
}

func (p *Plugin) disposeKeys(ctx context.Context) error {
	p.log.Debug("Looking for keys in trust domain to dispose")
	pager := p.keyVaultClient.NewListKeysPager(nil)
	now := p.hooks.clk.Now()
	maxStaleTime := now.Add(-maxStaleDuration)

	pd, err := p.getPluginData()
	if err != nil {
		return err
	}

	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			p.log.Error("Failed to list keys to dispose", reasonTag, err)
			return err
		}

		for _, key := range resp.Value {
			// Skip keys that do not belong to this trust domain
			trustDomain, hasTD := key.Tags[tagNameServerTrustDomain]
			if !hasTD || *trustDomain != pd.trustDomain {
				continue
			}

			// Keys are enqueued for deletion when they are rotated, so we skip
			// here the keys that belong to this server. Stale keys from other
			// servers in the trust domain are enqueued for deletion.
			if pd.serverID == *key.Tags[tagNameServerID] {
				continue
			}

			// If the key has not been updated for maxStaleDuration, enqueue it for deletion
			updated := key.Attributes.Updated
			if updated.Before(maxStaleTime) {
				keyName := key.KID.Name()
				select {
				case p.scheduleDelete <- keyName:
					p.log.Debug("Key enqueued for deletion", keyNameTag, keyName)
				default:
					p.log.Error("Failed to enqueue key for deletion", keyNameTag, keyName)
				}
			}
		}
	}
	return nil
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
	pd, err := p.getPluginData()
	if err != nil {
		return nil, err
	}

	// Build tags including the KID tag for shared keys mode
	tags := make(map[string]*string)
	for k, v := range p.keyTags {
		tags[k] = v
	}
	if pd.sharedKeysEnabled {
		tags[tagNameKeyID] = to.Ptr(spireKeyID)
	}

	createKeyParameters, err := getCreateKeyParameters(keyType, tags)
	if err != nil {
		return nil, err
	}

	keyName, err := p.generateKeyName(spireKeyID)
	if err != nil {
		return nil, fmt.Errorf("could not generate key name: %w", err)
	}

	// OPTIMIZATION: Check for the existing fresh key (Optimistic coordination) for Shared Keys
	if pd.sharedKeysEnabled {
		existingKey, err := p.keyVaultClient.GetKey(ctx, keyName, "", nil)
		if err == nil && existingKey.Key != nil {
			sharedKeyFreshnessThreshold := 15 * time.Minute
			if existingKey.KeyBundle.Attributes != nil && existingKey.KeyBundle.Attributes.Created != nil {
				if p.hooks.clk.Now().Sub(*existingKey.KeyBundle.Attributes.Created) < sharedKeyFreshnessThreshold {
					// Check if algorithm matches
					if keyTypeMatch(existingKey.KeyBundle, keyType) {
						p.log.Info("Shared key is already fresh. Reusing existing key (optimistic).", "key_name", keyName)

						rawKey, err := keyVaultKeyToRawKey(existingKey.Key)
						if err != nil {
							return nil, err
						}
						publicKey, err := x509.MarshalPKIXPublicKey(rawKey)
						if err != nil {
							return nil, status.Errorf(codes.Internal, "failed to marshal public key: %v", err)
						}

						return &keyEntry{
							KeyID:      string(*existingKey.Key.KID),
							KeyName:    existingKey.Key.KID.Name(),
							keyVersion: existingKey.Key.KID.Version(),
							PublicKey: &keymanagerv1.PublicKey{
								Id:          spireKeyID,
								Type:        keyType,
								PkixData:    publicKey,
								Fingerprint: makeFingerprint(publicKey),
							},
						}, nil
					}
				}
			}
		}
	}

	// Acquire Lock (if configured) for shared keys mode
	var lockTag string
	if pd.sharedKeysEnabled && pd.lockTagTemplate != nil {
		data := struct {
			TrustDomain string
			KeyID       string
		}{
			TrustDomain: pd.trustDomain,
			KeyID:       spireKeyID,
		}

		var buf strings.Builder
		if err := pd.lockTagTemplate.Execute(&buf, data); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to execute lock_tag_template: %v", err)
		}
		lockTag = buf.String()

		// We need to check if the key exists to lock it. If it doesn't exist, we can't lock it,
		// but we also don't need to lock it because we are creating it.
		// However, if we are rotating, the key name is the same (derived from template), so we check existence.
		latestKey, err := p.keyVaultClient.GetKey(ctx, keyName, "", nil)
		if err == nil {
			// Key exists, try to acquire lock
			if latestKey.Tags == nil {
				latestKey.Tags = make(map[string]*string)
			}

			if _, ok := latestKey.Tags[lockTag]; ok {
				p.log.Warn("Rotation lock held by another instance. Aborting rotation.", "lock_tag", lockTag)
				return nil, status.Errorf(codes.Aborted, "rotation lock held")
			}

			latestKey.Tags[lockTag] = to.Ptr("true")
			// Update tags to acquire lock
			_, err = p.keyVaultClient.UpdateKey(ctx, keyName, latestKey.Key.KID.Version(), azkeys.UpdateKeyParameters{
				Tags: latestKey.Tags,
			}, nil)

			if err != nil {
				p.log.Warn("Failed to acquire rotation lock (concurrent update). Aborting.", "error", err)
				return nil, status.Errorf(codes.Aborted, "failed to acquire lock: %v", err)
			}

			p.log.Debug("Acquired rotation lock", "lock_tag", lockTag)

			defer func() {
				// Release lock
				k, err := p.keyVaultClient.GetKey(ctx, keyName, "", nil)
				if err != nil {
					p.log.Error("Failed to get key to release lock", "error", err)
					return
				}
				if k.Tags != nil {
					delete(k.Tags, lockTag)
				}
				_, err = p.keyVaultClient.UpdateKey(ctx, keyName, k.Key.KID.Version(), azkeys.UpdateKeyParameters{
					Tags: k.Tags,
				}, nil)
				if err != nil {
					p.log.Error("Failed to release rotation lock", "lock_tag", lockTag, "error", err)
				} else {
					p.log.Debug("Released rotation lock", "lock_tag", lockTag)
				}
			}()
		}
	}

	// Check if the Key already has a fresh version (concurrency check)
	if pd.sharedKeysEnabled {
		existingKey, err := p.keyVaultClient.GetKey(ctx, keyName, "", nil)
		if err == nil && existingKey.Key != nil {
			sharedKeyFreshnessThreshold := 15 * time.Minute
			if existingKey.KeyBundle.Attributes != nil && existingKey.KeyBundle.Attributes.Created != nil {
				if p.hooks.clk.Now().Sub(*existingKey.KeyBundle.Attributes.Created) < sharedKeyFreshnessThreshold {
					if keyTypeMatch(existingKey.KeyBundle, keyType) {
						p.log.Info("Shared key was recently rotated by another instance. Reusing existing key.", "key_name", keyName)

						rawKey, err := keyVaultKeyToRawKey(existingKey.Key)
						if err != nil {
							return nil, err
						}
						publicKey, err := x509.MarshalPKIXPublicKey(rawKey)
						if err != nil {
							return nil, status.Errorf(codes.Internal, "failed to marshal public key: %v", err)
						}

						return &keyEntry{
							KeyID:      string(*existingKey.Key.KID),
							KeyName:    existingKey.Key.KID.Name(),
							keyVersion: existingKey.Key.KID.Version(),
							PublicKey: &keymanagerv1.PublicKey{
								Id:          spireKeyID,
								Type:        keyType,
								PkixData:    publicKey,
								Fingerprint: makeFingerprint(publicKey),
							},
						}, nil
					}
				}
			}
		}
	}

	createResp, err := p.keyVaultClient.CreateKey(ctx, keyName, *createKeyParameters, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create key: %v", err)
	}
	log := p.log.With(keyIDTag, *createResp.Key.KID)
	log.Debug("Key created", algorithmTag, *createResp.Key.Kty)

	rawKey, err := keyVaultKeyToRawKey(createResp.Key)
	if err != nil {
		return nil, err
	}
	publicKey, err := x509.MarshalPKIXPublicKey(rawKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal public key: %v", err)
	}

	if keyEntry, ok := p.getKeyEntry(spireKeyID); ok {
		// In shared keys mode, we might not want to delete the old key immediately if it's shared?
		// But here we are creating a NEW version (or new key if name changed).
		// If name is same (shared keys), CreateKey creates a new version.
		// The old version is still valid but we are switching to new one.
		// In standard mode, we delete the old key (which has a different name).
		// In shared keys mode, we are just adding a version. We probably shouldn't delete the KEY itself.
		// But wait, standard mode generates a NEW NAME for every rotation.
		// Shared keys mode reuses the NAME.
		// So in shared keys mode, we should NOT delete the key.
		if !pd.sharedKeysEnabled {
			select {
			case p.scheduleDelete <- keyEntry.KeyName:
				p.log.Debug("Key enqueued for deletion", keyNameTag, keyEntry.KeyName)
			default:
				p.log.Error("Failed to enqueue key for deletion", keyNameTag, keyEntry.KeyName)
			}
		}
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

func keyTypeMatch(keyBundle azkeys.KeyBundle, keyType keymanagerv1.KeyType) bool {
	kt, ok := keyTypeFromKeySpec(keyBundle)
	return ok && kt == keyType
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

// keyVaultSignatureToASN1Encoded converts the signature format from IEEE P1363 to ASN.1/DER for ECDSA signed messages
// If the message is RSA signed, it's just returned i.e: no conversion needed for RSA signed messages
// This is all because when the signing algorithm used is ECDSA, azure's Sign API produces an IEEE P1363 format response
// while we expect the RFC3279 ASN.1 DER Format during signature verification (ecdsa.VerifyASN1).
func keyVaultSignatureToASN1Encoded(keyVaultSigResult []byte, keyType keymanagerv1.KeyType) ([]byte, error) {
	isRSA := keyType == keymanagerv1.KeyType_RSA_2048 || keyType == keymanagerv1.KeyType_RSA_4096
	if isRSA {
		// No conversion needed, it's already ASN.1 encoded
		return keyVaultSigResult, nil
	}
	sigLength := len(keyVaultSigResult)
	// The sig byte array length must either be 64 (ec-p256) or 96 (ec-p384)
	if sigLength != 64 && sigLength != 96 {
		return nil, status.Errorf(codes.Internal, "malformed signature response")
	}
	rVal := new(big.Int)
	rVal.SetBytes(keyVaultSigResult[0 : sigLength/2])
	sVal := new(big.Int)
	sVal.SetBytes(keyVaultSigResult[sigLength/2 : sigLength])
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(rVal)
		b.AddASN1BigInt(sVal)
	})
	return b.Bytes()
}

// keyVaultKeyToRawKey takes a *azkeys.JSONWebKey and returns the corresponding raw public key
// For example *ecdsa.PublicKey or *rsa.PublicKey etc
func keyVaultKeyToRawKey(keyVaultKey *azkeys.JSONWebKey) (any, error) {
	// Marshal the key to JSON
	jwkJSON, err := keyVaultKey.MarshalJSON()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal key: %v", err)
	}

	// Parse JWK
	var key jose.JSONWebKey
	if err := json.Unmarshal(jwkJSON, &key); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse key: %v", err)
	}

	if key.Key == nil {
		return nil, status.Errorf(codes.Internal, "failed to convert Key Vault key to raw key: %v", err)
	}

	return key.Key, nil
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

// getPluginData gets the pluginData structure maintained by the plugin.
func (p *Plugin) getPluginData() (*pluginData, error) {
	p.pdMtx.RLock()
	defer p.pdMtx.RUnlock()

	if p.pd == nil {
		return nil, status.Error(codes.FailedPrecondition, "plugin data not yet initialized")
	}
	return p.pd, nil
}

// setPluginData sets the pluginData structure maintained by the plugin.
func (p *Plugin) setPluginData(pd *pluginData) {
	p.pdMtx.Lock()
	defer p.pdMtx.Unlock()

	p.pd = pd
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
					log.Error("Failed to schedule key deletion", reasonTag, "No such key")
					p.notifyDelete(err)
					continue
				}
			}
			// For any other error, log it and re-enqueue the key for deletion as it might be a recoverable error
			log.Error("It was not possible to schedule key for deletion. Trying to re-enqueue it for deletion", reasonTag, err)

			select {
			case p.scheduleDelete <- keyName:
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

func (p *Plugin) notifyDelete(err error) {
	if p.hooks.scheduleDeleteSignal != nil {
		p.hooks.scheduleDeleteSignal <- err
	}
}

func getCreateKeyParameters(keyType keymanagerv1.KeyType, keyTags map[string]*string) (*azkeys.CreateKeyParameters, error) {
	result := &azkeys.CreateKeyParameters{}
	switch keyType {
	case keymanagerv1.KeyType_RSA_2048:
		result.Kty = to.Ptr(azkeys.JSONWebKeyTypeRSA)
		result.KeySize = to.Ptr(int32(2048))
	case keymanagerv1.KeyType_RSA_4096:
		result.Kty = to.Ptr(azkeys.JSONWebKeyTypeRSA)
		result.KeySize = to.Ptr(int32(4096))
	case keymanagerv1.KeyType_EC_P256:
		result.Kty = to.Ptr(azkeys.JSONWebKeyTypeEC)
		result.Curve = to.Ptr(azkeys.JSONWebKeyCurveNameP256)
	case keymanagerv1.KeyType_EC_P384:
		result.Kty = to.Ptr(azkeys.JSONWebKeyTypeEC)
		result.Curve = to.Ptr(azkeys.JSONWebKeyCurveNameP384)
	default:
		return nil, status.Errorf(codes.Internal, "unsupported key type: %v", keyType)
	}
	// Specify the key operations as Sign and Verify
	result.KeyOps = append(result.KeyOps, to.Ptr(azkeys.JSONWebKeyOperationSign), to.Ptr(azkeys.JSONWebKeyOperationVerify))
	// Set the key tags
	result.Tags = keyTags
	return result, nil
}

// generateKeyName returns a new identifier to be used as a key name.
// The returned name has the form: spire-key-<UUID>-<SPIRE-KEY-ID>,
// where UUID is a new randomly generated UUID and SPIRE-KEY-ID is provided
// through the spireKeyID parameter.
// If shared keys are enabled, it uses the key_name_template instead.
func (p *Plugin) generateKeyName(spireKeyID string) (keyName string, err error) {
	pd, err := p.getPluginData()
	if err != nil {
		return "", err
	}

	if pd.sharedKeysEnabled {
		data := struct {
			TrustDomain string
			KeyID       string
		}{
			TrustDomain: pd.trustDomain,
			KeyID:       spireKeyID,
		}

		var buf strings.Builder
		if err := pd.keyNameTemplate.Execute(&buf, data); err != nil {
			return "", status.Errorf(codes.Internal, "failed to execute key_name_template: %v", err)
		}
		return buf.String(), nil
	}

	uniqueID, err := generateUniqueID()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s-%s-%s", keyNamePrefix, uniqueID, spireKeyID), nil
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

func (p *Plugin) setCache(keyEntries []*keyEntry) {
	// clean previous cache
	p.entriesMtx.Lock()
	defer p.entriesMtx.Unlock()
	p.entries = make(map[string]keyEntry)

	// add results to cache
	for _, e := range keyEntries {
		p.entries[e.PublicKey.Id] = *e
		p.log.Debug("Key loaded", keyIDTag, e.KeyID, keyNameTag, e.KeyName)
	}
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

// generateUniqueID returns a randomly generated UUID.
func generateUniqueID() (id string, err error) {
	u, err := uuid.NewV4()
	if err != nil {
		return "", status.Errorf(codes.Internal, "could not create a randomly generated UUID: %v", err)
	}

	return u.String(), nil
}

func makeFingerprint(pkixData []byte) string {
	s := sha256.Sum256(pkixData)
	return hex.EncodeToString(s[:])
}

func signingAlgorithmForKeyVault(keyType keymanagerv1.KeyType, signerOpts any) (azkeys.JSONWebKeySignatureAlgorithm, error) {
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
			return "", errors.New("invalid signerOpts. PSS options are required")
		}
		hashAlgo = opts.PssOptions.HashAlgorithm
		isPSS = true
		// opts.PssOptions.SaltLength is handled by Key Vault. The salt length matches the bits of the hashing algorithm.
	default:
		return "", fmt.Errorf("unsupported signer opts type %T", opts)
	}

	isRSA := keyType == keymanagerv1.KeyType_RSA_2048 || keyType == keymanagerv1.KeyType_RSA_4096

	switch {
	case hashAlgo == keymanagerv1.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM:
		return "", errors.New("hash algorithm is required")
	case keyType == keymanagerv1.KeyType_EC_P256 && hashAlgo == keymanagerv1.HashAlgorithm_SHA256:
		return azkeys.JSONWebKeySignatureAlgorithmES256, nil
	case keyType == keymanagerv1.KeyType_EC_P384 && hashAlgo == keymanagerv1.HashAlgorithm_SHA384:
		return azkeys.JSONWebKeySignatureAlgorithmES384, nil
	case isRSA && !isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA256:
		return azkeys.JSONWebKeySignatureAlgorithmRS256, nil
	case isRSA && !isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA384:
		return azkeys.JSONWebKeySignatureAlgorithmRS384, nil
	case isRSA && !isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA512:
		return azkeys.JSONWebKeySignatureAlgorithmRS512, nil
	case isRSA && isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA256:
		return azkeys.JSONWebKeySignatureAlgorithmPS256, nil
	case isRSA && isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA384:
		return azkeys.JSONWebKeySignatureAlgorithmPS384, nil
	case isRSA && isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA512:
		return azkeys.JSONWebKeySignatureAlgorithmPS512, nil
	default:
		return "", fmt.Errorf("unsupported combination of key type: %v and hashing algorithm: %v", keyType, hashAlgo)
	}
}
