package hashicorpvault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/andres-erbsen/clock"
	"github.com/gofrs/uuid/v5"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"github.com/spiffe/spire/pkg/server/common/vault"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	vault.BaseConfiguration `hcl:",squash"`

	KeyIdentifierFile  string `hcl:"key_identifier_file" json:"key_identifier_file"`
	KeyIdentifierValue string `hcl:"key_identifier_value" json:"key_identifier_value"`
	// TransitEnginePath specifies the path to the transit engine to perform key operations.
	TransitEnginePath string `hcl:"transit_engine_path" json:"transit_engine_path"`
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

	authMethod vault.AuthMethod
	cc         *vault.ClientConfig
	vc         *vault.Client

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
	config, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	serverID := config.KeyIdentifierValue
	p.logger.Debug("Loaded server id", "server_id", serverID)

	if config.InsecureSkipVerify {
		p.logger.Warn("TLS verification of Vault certificates is skipped. This is only recommended for test environments.")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	am, err := vault.ParseAuthMethod(&config.BaseConfiguration)
	if err != nil {
		return nil, err
	}
	cp, err := vault.GenClientParams(am, &config.BaseConfiguration, p.hooks.lookupEnv)
	if err != nil {
		return nil, err
	}
	cp.TransitEnginePath = p.getEnvOrDefault(vault.EnvVaultTransitEnginePath, config.TransitEnginePath)

	vcConfig, err := vault.NewClientConfig(cp, p.logger)
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

	if err := p.setCache(keyEntries); err != nil {
		return nil, err
	}

	// Cancel previous tasks in case of re-configure.
	if p.cancelTasks != nil {
		p.cancelTasks()
	}

	// start tasks
	ctx, p.cancelTasks = context.WithCancel(context.Background())
	go p.scheduleDeleteTask(ctx)

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(ctx context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *Config {
	newConfig := new(Config)

	if err := hcl.Decode(&newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	switch {
	case newConfig.KeyIdentifierFile != "" && newConfig.KeyIdentifierValue != "":
		status.ReportErrorf("only one of 'key_identifier_file' or 'key_identifier_value' should be provided")

	case newConfig.KeyIdentifierFile == "" && newConfig.KeyIdentifierValue == "":
		status.ReportErrorf("one of 'key_identifier_file' or 'key_identifier_value' must be provided")

	case newConfig.KeyIdentifierValue == "":
		// Generate or retrieve the Server ID if KeyIdentifierValue is not provided
		serverID, err := getOrCreateServerID(newConfig.KeyIdentifierFile)
		if err != nil {
			status.ReportErrorf("failed to generate or retrieve server ID: %v", err)
		}
		newConfig.KeyIdentifierValue = serverID
	}

	return newConfig
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

func algosForKMS(keyType keymanagerv1.KeyType, signerOpts any) (vault.TransitHashAlgorithm, vault.TransitSignatureAlgorithm, error) {
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
		return vault.TransitHashAlgorithmNone, vault.TransitSignatureSignatureAlgorithmPKCS1v15, nil
	case isRSA && !isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA256:
		return vault.TransitHashAlgorithmSHA256, vault.TransitSignatureSignatureAlgorithmPKCS1v15, nil
	case isRSA && !isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA384:
		return vault.TransitHashAlgorithmSHA384, vault.TransitSignatureSignatureAlgorithmPKCS1v15, nil
	case isRSA && !isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA512:
		return vault.TransitHashAlgorithmSHA512, vault.TransitSignatureSignatureAlgorithmPKCS1v15, nil
	case isRSA && isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA256:
		return vault.TransitHashAlgorithmSHA256, vault.TransitSignatureSignatureAlgorithmPSS, nil
	case isRSA && isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA384:
		return vault.TransitHashAlgorithmSHA384, vault.TransitSignatureSignatureAlgorithmPSS, nil
	case isRSA && isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA512:
		return vault.TransitHashAlgorithmSHA512, vault.TransitSignatureSignatureAlgorithmPSS, nil
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

	ve, err := p.vc.GetKey(ctx, keyName)
	if err != nil {
		return nil, err
	}

	return getKeyEntry(ve.KeyName, ve.KeyData)
}

func convertToTransitKeyType(keyType keymanagerv1.KeyType) (*vault.TransitKeyType, error) {
	switch keyType {
	case keymanagerv1.KeyType_EC_P256:
		return to.Ptr(vault.TransitKeyTypeECDSAP256), nil
	case keymanagerv1.KeyType_EC_P384:
		return to.Ptr(vault.TransitKeyTypeECDSAP384), nil
	case keymanagerv1.KeyType_RSA_2048:
		return to.Ptr(vault.TransitKeyTypeRSA2048), nil
	case keymanagerv1.KeyType_RSA_4096:
		return to.Ptr(vault.TransitKeyTypeRSA4096), nil
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

func (p *Plugin) setCache(vaultEntries []*vault.KeyEntry) error {
	// clean previous cache
	p.entriesMtx.Lock()
	defer p.entriesMtx.Unlock()
	p.entries = make(map[string]keyEntry)

	// add results to cache
	for _, ve := range vaultEntries {
		ke, err := getKeyEntry(ve.KeyName, ve.KeyData)
		if err != nil {
			return err
		}
		p.entries[ke.PublicKey.Id] = *ke
		p.logger.Debug("Key loaded", "key_id", ke.PublicKey.Id, "key_type", ke.PublicKey.Type)
	}
	return nil
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
