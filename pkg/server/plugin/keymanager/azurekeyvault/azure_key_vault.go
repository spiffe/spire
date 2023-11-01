package azurekeyvault

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
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
	"github.com/gofrs/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/lestrrat-go/jwx/v2/jwk"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/diskutil"
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
	KeyMetadataFile string `hcl:"key_metadata_file" json:"key_metadata_file"`
	KeyVaultURI     string `hcl:"key_vault_uri" json:"key_vault_uri"`
	TenantID        string `hcl:"tenant_id" json:"tenant_id"`
	SubscriptionID  string `hcl:"subscription_id" json:"subscription_id"`
	AppID           string `hcl:"app_id" json:"app_id"`
	AppSecret       string `hcl:"app_secret" json:"app_secret"`

	// Deprecated: use_msi is deprecated and will be removed in a future release.
	// Will be used implicitly if other mechanisms to authenticate fail.
	UseMSI bool `hcl:"use_msi" json:"use_msi"`
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
	serverID       string
	scheduleDelete chan string
	cancelTasks    context.CancelFunc
	hooks          pluginHooks
	keyTags        map[string]*string
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
	config, err := parseAndValidateConfig(req.HclConfiguration)
	if err != nil {
		return nil, err
	}

	serverID, err := getOrCreateServerID(config.KeyMetadataFile)
	if err != nil {
		return nil, err
	}
	p.log.Debug("Loaded server ID", "server_id", serverID)

	var client cloudKeyManagementService

	switch {
	case config.SubscriptionID != "", config.AppID != "", config.AppSecret != "", config.TenantID != "":
		if config.UseMSI {
			return nil, status.Errorf(codes.InvalidArgument, "invalid configuration, cannot use both MSI and app authentication")
		}
		if config.TenantID == "" {
			return nil, status.Errorf(codes.InvalidArgument, "invalid configuration, missing tenant id")
		}
		if config.SubscriptionID == "" {
			return nil, status.Errorf(codes.InvalidArgument, "invalid configuration, missing subscription id")
		}
		if config.AppID == "" {
			return nil, status.Errorf(codes.InvalidArgument, "invalid configuration, missing application id")
		}
		if config.AppSecret == "" {
			return nil, status.Errorf(codes.InvalidArgument, "invalid configuration, missing app secret")
		}

		creds, err := azidentity.NewClientSecretCredential(config.TenantID, config.AppID, config.AppSecret, nil)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to get client credential: %v", err)
		}

		client, err = p.hooks.newKeyVaultClient(creds, config.KeyVaultURI)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create Key Vault client with client credentials: %v", err)
		}

	case config.UseMSI:
		p.log.Warn("use_msi is deprecated and will be removed in a future release")
		fallthrough // use default credential which attempts to fetch credentials using MSI

	default:
		cred, err := p.hooks.fetchCredential()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to fetch client credential: %v", err)
		}
		client, err = p.hooks.newKeyVaultClient(cred, config.KeyVaultURI)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create Key Vault client with MSI credential: %v", err)
		}
	}

	fetcher := &keyFetcher{
		keyVaultClient: client,
		log:            p.log,
		serverID:       serverID,
		trustDomain:    req.CoreConfiguration.TrustDomain,
	}

	p.log.Debug("Fetching keys from Azure Key Vault", "key_vault_uri", config.KeyVaultURI)
	keyEntries, err := fetcher.fetchKeyEntries(ctx)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.setCache(keyEntries)
	p.keyVaultClient = client
	p.trustDomain = req.CoreConfiguration.TrustDomain
	p.serverID = serverID
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
		return fmt.Errorf(strings.Join(errs, ": "))
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
	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			p.log.Error("Failed to list keys to dispose", reasonTag, err)
			return err
		}

		for _, key := range resp.Value {
			// Skip keys that do not belong to this trust domain
			trustDomain, hasTD := key.Tags[tagNameServerTrustDomain]
			if !hasTD || *trustDomain != p.trustDomain {
				continue
			}

			// Keys are enqueued for deletion when they are rotated, so we skip
			// here the keys that belong to this server. Stale keys from other
			// servers in the trust domain are enqueued for deletion.
			if p.serverID == *key.Tags[tagNameServerID] {
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
		select {
		case p.scheduleDelete <- keyEntry.KeyName:
			p.log.Debug("Key enqueued for deletion", keyNameTag, keyEntry.KeyName)
		default:
			p.log.Error("Failed to enqueue key for deletion", keyNameTag, keyEntry.KeyName)
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
	key, err := jwk.ParseKey(jwkJSON)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse key: %v", err)
	}

	var rawkey any
	// Raw returns the public key represented by this JWK (in this case, *rsa.PublicKey or *ecdsa.PublicKey)
	if err := key.Raw(&rawkey); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to convert Key Vault key to raw key: %v", err)
	}
	return rawkey, nil
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

// min returns the minimum of the provided time durations.
func min(x, y time.Duration) time.Duration {
	if x < y {
		return x
	}
	return y
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
func (p *Plugin) generateKeyName(spireKeyID string) (keyName string, err error) {
	uniqueID, err := generateUniqueID()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s-%s-%s", keyNamePrefix, uniqueID, spireKeyID), nil
}

// parseAndValidateConfig returns an error if any configuration provided does not meet acceptable criteria
func parseAndValidateConfig(c string) (*Config, error) {
	config := new(Config)

	if err := hcl.Decode(config, c); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if config.KeyVaultURI == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is missing the Key Vault URI")
	}

	if config.KeyMetadataFile == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is missing server ID file path")
	}

	return config, nil
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
