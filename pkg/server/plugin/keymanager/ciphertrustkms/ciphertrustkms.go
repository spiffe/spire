package ciphertrustkms

import (
	"context"
	"crypto/sha1" //nolint: gosec // We use sha1 to hash trust domain names in 128 bytes to avoid label value restrictions
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/andres-erbsen/clock"
	"github.com/gofrs/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "ciphertrust_kms"

	algorithmTag             = "algorithm"
	cryptoKeyNameTag         = "crypto_key_name"
	cryptoKeyVersionNameTag  = "crypto_key_version_name"
	cryptoKeyVersionStateTag = "crypto_key_version_state"
	scheduledDestroyTimeTag  = "scheduled_destroy_time"
	reasonTag                = "reason"

	disposeCryptoKeysFrequency    = time.Hour * 24
	keepActiveCryptoKeysFrequency = time.Hour * 6
	maxStaleDuration              = time.Hour * 24 * 14 // Two weeks

	cryptoKeyNamePrefix = "spire-key"
	labelNameServerID   = "spire-server-id"
	labelNameLastUpdate = "spire-last-update"
	labelNameServerTD   = "spire-server-td"
	labelNameActive     = "spire-active"

	getPublicKeyMaxAttempts = 10
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

// Create our own definition of this structure but like ciphertrust needs.
// Do not remove this one, create another one or it will break the code
type keyEntryCipherTrust struct {
	cryptoKey            *Key
	cryptoKeyVersionName string
	publicKey            *keymanagerv1.PublicKey
}

type pluginHooks struct {
	newKMSClient func(context.Context, ...option.ClientOption) (cloudKeyManagementServiceCipherTrust, error)

	clk clock.Clock

	// Used for testing only.
	disposeCryptoKeysSignal    chan error
	enqueueDestructionSignal   chan error
	keepActiveCryptoKeysSignal chan error
}

type pluginData struct {
	serverID string
	tdHash   string
}

// Plugin is the main representation of this keymanager plugin.
type Plugin struct {
	keymanagerv1.UnsafeKeyManagerServer
	configv1.UnsafeConfigServer

	cancelTasks context.CancelFunc

	config     *Config
	configMtx  sync.RWMutex
	entries    map[string]keyEntryCipherTrust
	entriesMtx sync.RWMutex

	pd    *pluginData
	pdMtx sync.RWMutex

	hooks                pluginHooks
	kmsClientCipherTrust cloudKeyManagementServiceCipherTrust

	log             hclog.Logger
	scheduleDestroy chan string
}

// Config provides configuration context for the plugin.
type Config struct {
	// File path location where key metadata used by the plugin is persisted.
	KeyMetadataFile string `hcl:"key_metadata_file" json:"key_metadata_file"`
	// Where the CipherTrust instance is running.
	CTMService string `hcl:"ctm_url" json:"ctm_url"`
	// Username to access the CT instance.
	Username string `hcl:"username" json:"username"`
	// Password to access the CT instance.
	Password string `hcl:"password" json:"password"`
}

// New returns an instantiated plugin.
func New() *Plugin {
	return newPlugin(newKMSClient)
}

// newPlugin returns a new ciphertrsut plugin instance.
func newPlugin(
	newKMSClient func(context.Context, ...option.ClientOption) (cloudKeyManagementServiceCipherTrust, error),
) *Plugin {
	return &Plugin{
		entries: make(map[string]keyEntryCipherTrust),
		hooks: pluginHooks{
			newKMSClient: newKMSClient,
			clk:          clock.New(),
		},
		scheduleDestroy: make(chan string, 120),
	}
}

// Configure sets up the plugin.
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

	Init(config.CTMService, config.Username, config.Password)

	// Hash the trust domain name to avoid restrictions.
	tdHashBytes := sha1.Sum([]byte(req.CoreConfiguration.TrustDomain)) //nolint: gosec // We use sha1 to hash trust domain names in 128 bytes to avoid label restrictions
	tdHashString := hex.EncodeToString(tdHashBytes[:])

	p.setPluginData(&pluginData{
		serverID: serverID,
		tdHash:   tdHashString,
	})

	var opts []option.ClientOption

	kc, err := p.hooks.newKMSClient(ctx, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create Google Cloud KMS client: %v", err)
	}

	fetcher := &keyFetcher{
		kmsClientCipherTrust: kc,
		log:                  p.log,
		serverID:             serverID,
		tdHash:               tdHashString,
	}
	p.log.Debug("Fetching keys from Cloud KMS\n")
	keyEntries, err := fetcher.fetchKeyEntriesCipherTrust(ctx)
	if err != nil {
		return nil, err
	}

	p.setCacheCipherTrust(keyEntries)
	p.kmsClientCipherTrust = kc

	// Cancel previous tasks in case of re configure.
	if p.cancelTasks != nil {
		p.cancelTasks()
	}

	p.configMtx.Lock()
	defer p.configMtx.Unlock()
	p.config = config

	// Start long-running tasks.
	ctx, p.cancelTasks = context.WithCancel(context.Background())
	go p.keepActiveCryptoKeysTask(ctx)
	go p.disposeCryptoKeysTask(ctx)
	return &configv1.ConfigureResponse{}, nil
}

// GenerateKey creates a key in KMS. If a key already exists in the local storage,
// it is updated.
func (p *Plugin) GenerateKey(ctx context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.KeyType == keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE {
		return nil, status.Error(codes.InvalidArgument, "key type is required")
	}
	pubKey, err := p.createKey(ctx, req.KeyId, req.KeyType)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate key: %v", err)
	}

	return &keymanagerv1.GenerateKeyResponse{
		PublicKey: pubKey,
	}, nil
}

// GetPublicKey returns the public key for a given key
func (p *Plugin) GetPublicKey(ctx context.Context, req *keymanagerv1.GetPublicKeyRequest) (*keymanagerv1.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}

	entry, ok := p.getKeyEntryCipherTrust(req.KeyId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "key %q not found", req.KeyId)
	}

	return &keymanagerv1.GetPublicKeyResponse{
		PublicKey: entry.publicKey,
	}, nil
}

// GetPublicKeys returns the publicKey for all the keys.
func (p *Plugin) GetPublicKeys(context.Context, *keymanagerv1.GetPublicKeysRequest) (*keymanagerv1.GetPublicKeysResponse, error) {
	var keys []*keymanagerv1.PublicKey
	p.entriesMtx.RLock()
	defer p.entriesMtx.RUnlock()
	for _, key := range p.entries {
		keys = append(keys, key.publicKey)
	}

	return &keymanagerv1.GetPublicKeysResponse{PublicKeys: keys}, nil
}

// SetLogger sets a logger.
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// SignData creates a digital signature for the data to be signed.
func (p *Plugin) SignData(ctx context.Context, req *keymanagerv1.SignDataRequest) (*keymanagerv1.SignDataResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.SignerOpts == nil {
		return nil, status.Error(codes.InvalidArgument, "signer opts is required")
	}

	keyEntry, hasKey := p.getKeyEntryCipherTrust(req.KeyId)
	if !hasKey {
		return nil, status.Errorf(codes.NotFound, "key %q not found", req.KeyId)
	}

	switch opts := req.SignerOpts.(type) {
	case *keymanagerv1.SignDataRequest_HashAlgorithm:
		//hashAlgo = opts.HashAlgorithm
	case *keymanagerv1.SignDataRequest_PssOptions:
		// RSASSA-PSS is not supported by this plugin.
		// See the comment in cryptoKeyVersionAlgorithmFromKeyType function for
		// more details.
		return nil, status.Error(codes.InvalidArgument, "the only RSA signature scheme supported is RSASSA-PKCS1-v1_5")
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported signer opts type %T", opts)
	}

	signResp, err := p.kmsClientCipherTrust.AsymmetricSignCipherTrust(ctx, keyEntry.cryptoKey.Name, keyEntry.cryptoKey.Version, req.Data)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to sign: %v", err)
	}
	signatureBytes, err := hex.DecodeString(signResp.Signature)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to decode signature")
	}

	p.log.Debug("<- Signature received from CipherTrust\n")
	p.log.Debug(fmt.Sprintf("%x\n", signatureBytes))

	return &keymanagerv1.SignDataResponse{
		Signature:      signatureBytes,
		KeyFingerprint: keyEntry.publicKey.Fingerprint,
	}, nil
}

// createKey creates a new CryptoKey with a new CryptoKeyVersion in Cloud KMS
// if there is not already a cached entry with the specified SPIRE Key ID.
// If the cache already has an entry with this SPIRE Key ID, a new
// CryptoKeyVersion is added to the corresponding CryptoKey in Cloud KMS and the
// old CryptoKeyVersion is enqueued for destruction.
// This function requests Cloud KMS to get the public key of the created CryptoKeyVersion.
// A keyEntry is returned  with the CryptoKey, CryptoKeyVersion and public key.
func (p *Plugin) createKey(ctx context.Context, spireKeyID string, keyType keymanagerv1.KeyType) (*keymanagerv1.PublicKey, error) {
	// If we already have this SPIRE Key ID cached, a new CryptoKeyVersion is
	// added to the existing CryptoKey and the cache is updated. The old
	// CryptoKeyVersion is enqueued for destruction.
	if entry, ok := p.getKeyEntryCipherTrust(spireKeyID); ok {
		return p.addCryptoKeyVersionToCachedEntryCipherTrust(ctx, entry, spireKeyID, keyType)
	}

	algorithm, err := cryptoKeyVersionAlgorithmFromKeyType(keyType)
	if err != nil {
		return nil, err
	}

	cryptoKeyID, err := p.generateCryptoKeyID(spireKeyID)
	if err != nil {
		return nil, fmt.Errorf("could not generate CryptoKeyID: %w", err)
	}

	cryptoKeyLabels, err := p.getCryptoKeyLabels()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not get CryptoKey labels: %v", err)
	}
	cryptoKeyCipherTrust, err := p.kmsClientCipherTrust.CreateCryptoKeyCipherTrust(ctx, cryptoKeyID, cryptoKeyLabels)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create CryptoKey: %v", err)
	}

	log := p.log.With(cryptoKeyNameTag, cryptoKeyCipherTrust.Key.Name)
	log.Debug("CryptoKey created", algorithmTag, algorithm)

	cryptoKeyVersionName := cryptoKeyCipherTrust.Key.Name + "/cryptoKeyVersions/0"
	log.Debug("CryptoKeyVersion version added", cryptoKeyVersionNameTag, cryptoKeyVersionName)

	log.Debug("Public Key Created by CipherTrust\n", cryptoKeyCipherTrust.Key.PublicKey)

	pemBlock, _ := pem.Decode([]byte(cryptoKeyCipherTrust.Key.PublicKey))

	newKeyEntry := keyEntryCipherTrust{
		cryptoKey:            &cryptoKeyCipherTrust.Key,
		cryptoKeyVersionName: cryptoKeyVersionName,
		publicKey: &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    pemBlock.Bytes,
			Fingerprint: makeFingerprint(pemBlock.Bytes),
		},
	}

	p.setKeyEntryCipherTrust(spireKeyID, newKeyEntry)
	return newKeyEntry.publicKey, nil
}

// addCryptoKeyVersionToCachedEntry adds a new CryptoKeyVersion to an existing
// CryptoKey, updating the cached entries.
func (p *Plugin) addCryptoKeyVersionToCachedEntryCipherTrust(ctx context.Context, entry keyEntryCipherTrust, spireKeyID string, keyType keymanagerv1.KeyType) (*keymanagerv1.PublicKey, error) {
	algorithm, err := cryptoKeyVersionAlgorithmFromKeyType(keyType)
	if err != nil {
		return nil, err
	}

	log := p.log.With(cryptoKeyNameTag, entry.cryptoKey.Name, algorithm)

	cryptoKey, err := p.kmsClientCipherTrust.CreateCryptoKeyVersionCipherTrust(ctx, entry.cryptoKey.Name)

	if err != nil {
		return nil, fmt.Errorf("failed to create CryptoKeyVersion: %w", err)
	}
	log.Debug("CryptoKeyVersion added", cryptoKeyVersionNameTag, cryptoKey.Key.Name+"/"+strconv.Itoa(cryptoKey.Key.Version))

	log.Debug("CryptoKeyVersion added Public key ", cryptoKey.Key.PublicKey)

	pemBlock, _ := pem.Decode([]byte(cryptoKey.Key.PublicKey))

	log.Debug("public key byte from private key : ", pemBlock.Bytes)

	newKeyEntry := keyEntryCipherTrust{
		cryptoKey:            &cryptoKey.Key,
		cryptoKeyVersionName: cryptoKey.Key.Name + "/" + strconv.Itoa(cryptoKey.Key.Version),
		publicKey: &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    pemBlock.Bytes,
			Fingerprint: makeFingerprint(pemBlock.Bytes),
		},
	}

	p.setKeyEntryCipherTrust(spireKeyID, newKeyEntry)

	if err := p.enqueueDestruction(entry.cryptoKeyVersionName); err != nil {
		log.Error("Failed to enqueue CryptoKeyVersion for destruction", reasonTag, err)
	}

	return newKeyEntry.publicKey, nil
}

// disposeCryptoKeys looks for active CryptoKeys that haven't been updated
// during the maxStaleDuration time window. Those keys are then enqueued for
// destruction.
func (p *Plugin) disposeCryptoKeys(ctx context.Context) error {
	p.log.Debug("Dispose CryptoKeys")

	itCryptoKeys, err := p.kmsClientCipherTrust.ListCryptoKeysCipherTrust(ctx, "")
	if err != nil {
		p.log.Debug("Dispose CryptoKeys", err)
	}

	it := itCryptoKeys.createKeyIterator()

	for {
		cryptoKey, ok := it.getNext()
		if !ok {
			break
		}
		// mark it as inactive so it's not returned future calls.
		p.setDeactivated(ctx, cryptoKey)

	}
	return nil
}

// disposeCryptoKeysTask will be run every 24hs.
// It will schedule the destruction of CryptoKeyVersions that have a
// spire-last-update label value older than two weeks.
// It will only schedule the destruction of CryptoKeyVersions belonging to the
// current trust domain but not the current server. The spire-server-td and
// spire-server-id labels are used to identify the trust domain and server.
func (p *Plugin) disposeCryptoKeysTask(ctx context.Context) {
	ticker := p.hooks.clk.Ticker(disposeCryptoKeysFrequency)
	defer ticker.Stop()

	p.notifyDisposeCryptoKeys(nil)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := p.disposeCryptoKeys(ctx)
			p.notifyDisposeCryptoKeys(err)
		}
	}
}

// enqueueDestruction enqueues the specified CryptoKeyVersion for destruction.
func (p *Plugin) enqueueDestruction(cryptoKeyVersionName string) (err error) {
	select {
	case p.scheduleDestroy <- cryptoKeyVersionName:
		p.log.Debug("CryptoKeyVersion enqueued for destruction", cryptoKeyVersionNameTag, cryptoKeyVersionName)
	default:
		err = fmt.Errorf("could not enqueue CryptoKeyVersion %q for destruction", cryptoKeyVersionName)
	}

	p.notifyEnqueueDestruction(err)
	return err
}

// getCryptoKeyLabels gets the labels that must be set to a new CryptoKey
// that is being created.
func (p *Plugin) getCryptoKeyLabels() (map[string]string, error) {
	pd, err := p.getPluginData()
	if err != nil {
		return nil, err
	}
	return map[string]string{
		labelNameServerTD: pd.tdHash,
		labelNameServerID: pd.serverID,
		labelNameActive:   "true",
	}, nil
}

// getKeyEntry gets the entry from the cache that matches the provided
// SPIRE Key ID
func (p *Plugin) getKeyEntryCipherTrust(keyID string) (ke keyEntryCipherTrust, ok bool) {
	p.entriesMtx.RLock()
	defer p.entriesMtx.RUnlock()

	ke, ok = p.entries[keyID]
	return ke, ok
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

// setKeyEntry gets the entry from the cache that matches the provided
// SPIRE Key ID
func (p *Plugin) setKeyEntryCipherTrust(keyID string, ke keyEntryCipherTrust) {
	p.entriesMtx.Lock()
	defer p.entriesMtx.Unlock()

	p.entries[keyID] = ke
}

// setPluginData sets the pluginData structure maintained by the plugin.
func (p *Plugin) setPluginData(pd *pluginData) {
	p.pdMtx.Lock()
	defer p.pdMtx.Unlock()

	p.pd = pd
}

// keepActiveCryptoKeys keeps CryptoKeys managed by this plugin active updating
// the spire-last-update label with the current Unix time.
func (p *Plugin) keepActiveCryptoKeys(ctx context.Context) error {
	p.log.Debug("Keeping CryptoKeys managed by this server active")

	p.entriesMtx.Lock()
	defer p.entriesMtx.Unlock()
	var errs []string
	for _, entry := range p.entries {
		entry.cryptoKey.Labels[labelNameLastUpdate] = fmt.Sprint(p.hooks.clk.Now().Unix())
	}

	if errs != nil {
		return fmt.Errorf(strings.Join(errs, "; "))
	}
	return nil
}

// keepActiveCryptoKeysTask updates the CryptoKeys in the cache every 6 hours,
// setting the spire-last-update label to the current (Unix) time.
// This is done to be able to detect CryptoKeys that are inactive (not in use
// by any server).
func (p *Plugin) keepActiveCryptoKeysTask(ctx context.Context) {
	ticker := p.hooks.clk.Ticker(keepActiveCryptoKeysFrequency)
	defer ticker.Stop()

	p.notifyKeepActiveCryptoKeys(nil)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := p.keepActiveCryptoKeys(ctx)
			p.notifyKeepActiveCryptoKeys(err)
		}
	}
}

func (p *Plugin) notifyDisposeCryptoKeys(err error) {
	if p.hooks.disposeCryptoKeysSignal != nil {
		p.hooks.disposeCryptoKeysSignal <- err
	}
}

func (p *Plugin) notifyEnqueueDestruction(err error) {
	if p.hooks.enqueueDestructionSignal != nil {
		p.hooks.enqueueDestructionSignal <- err
	}
}

func (p *Plugin) notifyKeepActiveCryptoKeys(err error) {
	if p.hooks.keepActiveCryptoKeysSignal != nil {
		p.hooks.keepActiveCryptoKeysSignal <- err
	}
}

// setDeactivated updates the state in the specified CryptoKey to
// indicate that is deactivated.
func (p *Plugin) setDeactivated(ctx context.Context, cryptoKey *Key) {
	log := p.log.With(cryptoKeyNameTag, cryptoKey)

	cryptoKey.State = "Deactivated"
	_, err := p.kmsClientCipherTrust.UpdateCryptoKeyCipherTrust(ctx, cryptoKey)
	if err != nil {
		log.Error("Could not update CryptoKey as deactivated", reasonTag, err)
	}

	log.Debug("CryptoKey updated as deactivated", cryptoKeyNameTag, cryptoKey.Name)
	p.notifyDisposeCryptoKeys(err)
}

// setCacheCipherTrust sets the cached entries with the provided entries.
func (p *Plugin) setCacheCipherTrust(keyEntries []*keyEntryCipherTrust) {
	p.entriesMtx.Lock()
	defer p.entriesMtx.Unlock()

	p.entries = make(map[string]keyEntryCipherTrust)

	for _, e := range keyEntries {
		p.entries[e.publicKey.Id] = *e
		p.log.Debug("Cloud KMS key loaded", cryptoKeyVersionNameTag, e.cryptoKeyVersionName, algorithmTag)
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

// cryptoKeyVersionAlgorithmFromKeyType gets the corresponding algorithm of the
// CryptoKeyVersion from the provided key type.
// The returned CryptoKeyVersion_CryptoKeyVersionAlgorithm indicates the
// parameters that must be used for signing.
func cryptoKeyVersionAlgorithmFromKeyType(keyType keymanagerv1.KeyType) (kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, error) {
	// CryptoKeyVersion_CryptoKeyVersionAlgorithm specifies the padding algorithm
	// and the digest algorithm for RSA signatures. The key type in the Key
	// Manager interface does not contain the information about these parameters
	// for signing. Currently, there is no way in SPIRE to specify custom
	// parameters when signing through the ca.ServerCA interface and
	// x509.CreateCertificate defaults to RSASSA-PKCS-v1_5 as the padding
	// algorithm and a SHA256 digest. Therefore, for RSA signing keys we
	// choose the corresponding CryptoKeyVersion_CryptoKeyVersionAlgorithm using
	// RSASSA-PKCS-v1_5 for padding and a SHA256 digest.
	switch {
	case keyType == keymanagerv1.KeyType_EC_P256:
		return kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, nil
	case keyType == keymanagerv1.KeyType_EC_P384:
		return kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384, nil
	case keyType == keymanagerv1.KeyType_RSA_2048:
		return kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256, nil
	case keyType == keymanagerv1.KeyType_RSA_4096:
		return kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256, nil
	default:
		return kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED, fmt.Errorf("unsupported key type %q", keyType)
	}
}

// generateCryptoKeyID returns a new identifier to be used as a CryptoKeyID.
// The returned identifier has the form: spire-key-<UUID>-<SPIRE-KEY-ID>,
// where UUID is a new randomly generated UUID and SPIRE-KEY-ID is provided
// through the spireKeyID paramenter.
func (p *Plugin) generateCryptoKeyID(spireKeyID string) (cryptoKeyID string, err error) {
	pd, err := p.getPluginData()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s-%s", cryptoKeyNamePrefix, pd.serverID, spireKeyID), nil
}

// generateUniqueID returns a randomly generated UUID.
func generateUniqueID() (id string, err error) {
	u, err := uuid.NewV4()
	if err != nil {
		return "", status.Errorf(codes.Internal, "could not create a randomly generated UUID: %v", err)
	}

	return u.String(), nil
}

// getOrCreateServerID gets the server ID from the specified file path or creates
// a new server ID if the file does not exist.
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

// getPublicKeyFromCryptoKeyVersion requests Cloud KMS to get the public key
// of the specified CryptoKeyVersion.
func getPublicKeyFromCryptoKeyVersionCipherTrust(ctx context.Context, log hclog.Logger, kmsClientCipherTrust cloudKeyManagementServiceCipherTrust, key *Key) ([]byte, error) {
	kmsPublicKey, errGetPublicKey := kmsClientCipherTrust.GetPublicKeyCipherTrust(ctx, key)
	attempts := 1

	log = log.With(cryptoKeyVersionNameTag, key.Name+"/cryptoKeyVersions/"+strconv.Itoa(key.Version))
	for errGetPublicKey != nil {
		if attempts > getPublicKeyMaxAttempts {
			log.Error("Could not get the public key because the CryptoKeyVersion is still being generated. Maximum number of attempts reached.")
			return nil, errGetPublicKey
		}

		// Check if the CryptoKeyVersion is still being generated or
		// if it is now enabled.
		// Longer generation times can be observed when using algorithms
		// with large key sizes. (e.g. when rsa-4096 keys are used).
		// One or two additional attempts is usually enough to find the
		// CryptoKeyVersion enabled.
		switch kmsPublicKey.Key.State {
		case "Pre-Active":
			// This is a recoverable error.
		case "Active":
			// The CryptoKeyVersion may be ready to be used now.
		default:
			// We cannot recover if it's in a different status.
			return nil, errGetPublicKey
		}

		log.Warn("Could not get the public key because the CryptoKeyVersion is still being generated. Trying again.")
		attempts++
		kmsPublicKey, errGetPublicKey = kmsClientCipherTrust.GetPublicKeyCipherTrust(ctx, key)
	}

	pemBlock, _ := pem.Decode([]byte(kmsPublicKey.Key.PublicKey))

	log.Debug("Public Key from CipherTrust: \n", pemBlock.Bytes)
	return pemBlock.Bytes, nil
}

func makeFingerprint(pkixData []byte) string {
	s := sha256.Sum256(pkixData)
	return hex.EncodeToString(s[:])
}

// parseAndValidateConfig returns an error if any configuration provided does
// not meet acceptable criteria
func parseAndValidateConfig(c string) (*Config, error) {
	config := new(Config)

	if err := hcl.Decode(config, c); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if config.CTMService == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is missing the CipherTrust service URL")
	}
	if config.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is missing the CipherTrust service Username")
	}
	if config.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is missing CipherTrust service Password")
	}

	if config.KeyMetadataFile == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is missing server ID file path")
	}

	return config, nil
}
