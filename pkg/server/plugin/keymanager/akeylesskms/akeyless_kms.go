package akeylesskms

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"sync"

	"github.com/akeylesslabs/akeyless-go/v3"
	log "github.com/hashicorp/go-hclog"

	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// This compile-time assertion ensures the plugin conforms properly to the
	// pluginsdk.NeedsLogger interface.
	// TODO: Remove if the plugin does not need the logger.
	_ pluginsdk.NeedsLogger = (*Plugin)(nil)

	// This compile-time assertion ensures the plugin conforms properly to the
	// pluginsdk.NeedsHostServices interface.
	// TODO: Remove if the plugin does not need host services.
	_ pluginsdk.NeedsHostServices = (*Plugin)(nil)
)

const (
	pluginName    = "akeyless_kms"
	pluginKeyTag  = "spire-kms"
	pluginKeyType = "classic-key"
)

type keyEntry struct {
	DisplayId string
	PublicKey *keymanagerv1.PublicKey
}

// Plugin implements the KeyManager plugin
type Plugin struct {
	keymanagerv1.UnsafeKeyManagerServer
	configv1.UnsafeConfigServer

	mu sync.RWMutex

	entries                      map[string]keyEntry
	config                       *Config
	authenticationRoutineRunning bool

	// The logger received from the framework via the SetLogger method
	logger log.Logger
}

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		keymanagerv1.KeyManagerPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

func extractDerKey(pemKey string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, fmt.Errorf("failed to decode pem block")
	}
	return block.Bytes, nil
}

func fetchPublicKey(ctx context.Context, keyName string) ([]byte, error) {
	exportPublicKey := true
	body := akeyless.ExportClassicKey{ExportPublicKey: &exportPublicKey}
	body.SetName(keyName)
	body.SetToken(GetAuthToken())
	out, _, err := AklClient.ExportClassicKey(ctx).Body(body).Execute()
	if err != nil {
		return nil, extractAkeylessError(err, "export classic key")
	}

	if out.Key == nil || len(out.GetKey()) == 0 {
		return nil, fmt.Errorf("malformed get public key response")
	}

	return extractDerKey(out.GetKey())
}

// getKeyEntry gets the entry from the cache that matches the provided SPIRE Key ID
func (p *Plugin) getKeyEntry(keyID string) (keyEntry, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	ke, ok := p.entries[keyID]
	return ke, ok
}

// setKeyEntry gets the entry from the cache that matches the provided SPIRE Key ID
func (p *Plugin) setKeyEntry(keyID string, ke keyEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.entries[keyID] = ke
}

func (p *Plugin) setCache(keyEntries []*keyEntry) {
	// clean previous cache
	p.entries = make(map[string]keyEntry)

	// add results to cache
	for _, e := range keyEntries {
		p.entries[e.PublicKey.Id] = *e
		p.logger.Debug("Key loaded", e.DisplayId, e.PublicKey.Id)
	}
}

// GenerateKey implements the KeyManager GenerateKey RPC. Generates a new private key with the given ID.
// If a key already exists under that ID, it is overwritten and given a different fingerprint.
func (p *Plugin) GenerateKey(ctx context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.KeyType == keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE {
		return nil, status.Error(codes.InvalidArgument, "key type is required")
	}

	keySpec := keySpecFromKeyType(req.KeyType)
	if keySpec == "" {
		return nil, status.Errorf(codes.Internal, fmt.Sprintf("unsupported key type: %v", req.KeyType))
	}

	keyName := buildKeyName(req.KeyId, p.config)

	body := akeyless.CreateClassicKey{}
	body.SetAlg(keySpec)
	body.SetName(keyName)
	body.SetTags([]string{pluginKeyTag})
	body.SetToken(GetAuthToken())

	out, _, err := AklClient.CreateClassicKey(ctx).Body(body).Execute()
	if err != nil {
		return nil, extractAkeylessError(err, "create classic key")
	}

	if out.PublicKey == nil {
		return nil, status.Errorf(codes.Internal, "public key has not been returned after creation: %v", keyName)
	}

	publicKey, err := extractDerKey(out.GetPublicKey())
	if err != nil {
		return nil, status.Errorf(codes.Internal, fmt.Sprintf("failed to extract public key: %v", err.Error()))
	}

	pk := &keymanagerv1.PublicKey{
		Id:          req.KeyId,
		Type:        req.KeyType,
		PkixData:    publicKey,
		Fingerprint: makeFingerprint(publicKey),
	}

	p.setKeyEntry(keyName, keyEntry{DisplayId: out.GetClassicKeyId(), PublicKey: pk})

	return &keymanagerv1.GenerateKeyResponse{
		PublicKey: pk,
	}, nil
}

// GetPublicKey implements the KeyManager GetPublicKey RPC. Gets the public key information for the private key managed
// by the plugin with the given ID. If a key with the given ID does not exist, NOT_FOUND is returned.
func (p *Plugin) GetPublicKey(ctx context.Context, req *keymanagerv1.GetPublicKeyRequest) (*keymanagerv1.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}

	keyName := buildKeyName(req.KeyId, p.config)
	entry, ok := p.getKeyEntry(keyName)
	if !ok {
		return nil, status.Errorf(codes.NotFound, fmt.Sprintf("key %v not found", keyName))
	}

	return &keymanagerv1.GetPublicKeyResponse{
		PublicKey: entry.PublicKey,
	}, nil
}

// GetPublicKeys implements the KeyManager GetPublicKeys RPC. Gets all public key information for the private keys
// managed by the plugin.
func (p *Plugin) GetPublicKeys(ctx context.Context, req *keymanagerv1.GetPublicKeysRequest) (*keymanagerv1.GetPublicKeysResponse, error) {
	var keys []*keymanagerv1.PublicKey

	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, key := range p.entries {
		keys = append(keys, key.PublicKey)
	}

	return &keymanagerv1.GetPublicKeysResponse{PublicKeys: keys}, nil
}

// SignData implements the KeyManager SignData RPC. Signs data with the private key identified by the given ID. If a key
// with the given ID does not exist, NOT_FOUND is returned. The response contains the signed data and the fingerprint of
// the key used to sign the data. See the PublicKey message for more details on the role of the fingerprint.
func (p *Plugin) SignData(ctx context.Context, req *keymanagerv1.SignDataRequest) (*keymanagerv1.SignDataResponse, error) {

	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}

	keyName := buildKeyName(req.KeyId, p.config)
	entry, ok := p.getKeyEntry(keyName)
	if !ok {
		return nil, status.Errorf(codes.NotFound, fmt.Sprintf("key %v not found", keyName))
	}

	hashAlg, err := defineHashingAlgorithm(entry.PublicKey.Type, req.SignerOpts)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	body := akeyless.SignDataWithClassicKey{}
	body.SetToken(GetAuthToken())
	body.SetHashed(true)
	body.SetName(keyName)
	body.SetHashingMethod(hashAlg)
	body.SetVersion(1)
	body.SetData(base64.StdEncoding.EncodeToString(req.Data))

	signOut, _, err := AklClient.SignDataWithClassicKey(ctx).Body(body).Execute()
	if err != nil {
		return nil, extractAkeylessError(err, "sign data")
	}
	signed, err := base64.StdEncoding.DecodeString(signOut.GetResult())
	if err != nil {
		return nil, status.Errorf(codes.Internal, fmt.Sprintf("failed to decode signture: %v", err.Error()))
	}

	return &keymanagerv1.SignDataResponse{
		Signature:      signed,
		KeyFingerprint: entry.PublicKey.Fingerprint,
	}, nil
}

// Configure configures the plugin. This is invoked by SPIRE when the plugin is
// first loaded. In the future, it may be invoked to reconfigure the plugin.
// As such, it should replace the previous configuration atomically.
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config, err := ParseAndValidateConfig(req, p.logger)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.authenticationRoutineRunning {
		p.logger.Info(fmt.Sprintf("starting authentication routine to %v", config.AkeylessGatewayURL))
		closed := make(chan bool, 1)
		err = config.StartAuthentication(ctx, closed)

		if err != nil {
			p.logger.Error(fmt.Sprintf("failed to start authentication routine, error: %v", err.Error()))
			return nil, err
		}

		p.authenticationRoutineRunning = true
	}

	fetcher := &keyFetcher{
		log: p.logger,
	}
	p.logger.Debug("Fetching keys from Akeyless")
	keyEntries, err := fetcher.fetchKeyEntries(ctx)
	if err != nil {
		return nil, err
	}

	p.setCache(keyEntries)
	p.config = config

	return &configv1.ConfigureResponse{}, nil
}

// BrokerHostServices is called by the framework when the plugin is loaded to
// give the plugin a chance to obtain clients to SPIRE host services.
// TODO: Remove if the plugin does not need host services.
func (p *Plugin) BrokerHostServices(broker pluginsdk.ServiceBroker) error {
	// TODO: Use the broker to obtain host service clients
	return nil
}

// SetLogger is called by the framework when the plugin is loaded and provides
// the plugin with a logger wired up to SPIRE's logging facilities.
// TODO: Remove if the plugin does not need the logger.
func (p *Plugin) SetLogger(logger log.Logger) {
	p.logger = logger
}

// getConfig gets the configuration under a read lock.
func (p *Plugin) getConfig() (*Config, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func New() *Plugin {
	return &Plugin{
		entries: make(map[string]keyEntry),
		logger:  log.Default(),
	}
}

func main() {
	plugin := New()
	// Serve the plugin. This function call will not return. If there is a
	// failure to serve, the process will exit with a non-zero exit code.
	pluginmain.Serve(
		keymanagerv1.KeyManagerPluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}
