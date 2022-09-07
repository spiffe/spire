package gcpkms

import (
	"context"
	"crypto/sha1" //nolint: gosec // We use sha1 to hash trust domain names in 128 bytes to avoid label value restrictions
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/iam"
	"github.com/andres-erbsen/clock"
	"github.com/gofrs/uuid"
	"github.com/googleapis/gax-go/v2"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	iampb "google.golang.org/genproto/googleapis/iam/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

const (
	pluginName = "gcp_kms"

	algorithmTag            = "algorithm"
	cryptoKeyNameTag        = "crypto_key_name"
	cryptoKeyVersionNameTag = "crypto_key_version_name"
	reasonTag               = "reason"

	disposeCryptoKeysFrequency    = time.Hour * 48
	keepActiveCryptoKeysFrequency = time.Hour * 6
	maxStaleDuration              = time.Hour * 24 * 14 // Two weeks.

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
	cryptoKey        *kmspb.CryptoKey
	cryptoKeyVersion *kmspb.CryptoKeyVersion
	publicKey        *keymanagerv1.PublicKey
}

type listCryptoKeysFn func(ctx context.Context, kmsClient kmsClient, req *kmspb.ListCryptoKeysRequest, opts ...gax.CallOption) cryptoKeyIterator

type pluginHooks struct {
	newKMSClient     func(context.Context, ...option.ClientOption) (kmsClient, error)
	newOauth2Service func(context.Context, ...option.ClientOption) (oauth2Service, error)
	listCryptoKeys   listCryptoKeysFn

	clk clock.Clock

	// Used for testing only.
	disposeKeysSignal          chan error
	keepActiveCryptoKeysSignal chan error
	scheduleDestroySignal      chan error
}

// Plugin is the main representation of this keymanager plugin.
type Plugin struct {
	keymanagerv1.UnsafeKeyManagerServer
	configv1.UnsafeConfigServer

	cancelTasks context.CancelFunc

	config    *Config
	configMtx sync.RWMutex

	entries    map[string]keyEntry
	entriesMtx sync.RWMutex

	hooks           pluginHooks
	kmsClient       kmsClient
	log             hclog.Logger
	oauth2Service   oauth2Service
	scheduleDestroy chan *kmspb.CryptoKey
}

// Config provides configuration context for the plugin.
type Config struct {
	// File path location where key metadata used by the plugin is persisted.
	KeyMetadataFile string `hcl:"key_metadata_file" json:"key_metadata_file"`

	// File path location to a custom IAM Policy (v3) that will be set to
	// created CryptoKeys.
	KeyPolicyFile string `hcl:"key_policy_file" json:"key_policy_file"`

	// KeyRing is the resource ID of the key ring where the keys managed by this
	// plugin reside, in the format projects/*/locations/*/keyRings/*.
	KeyRing string `hcl:"key_ring" json:"key_ring"`

	// Path to the service account file used to authenticate with the Cloud KMS
	// API. If not specified, the value of the GOOGLE_APPLICATION_CREDENTIALS
	// environment variable is used.
	ServiceAccountFile string `hcl:"service_account_file" json:"service_account_file"`

	keyPolicy *string
	tdHash    string
	serverID  string
}

// New returns an instantiated plugin.
func New() *Plugin {
	return newPlugin(newKMSClient, newOauth2Service, listCryptoKeys)
}

// newPlugin returns a new plugin instance.
func newPlugin(
	newKMSClient func(context.Context, ...option.ClientOption) (kmsClient, error),
	newOauth2Service func(context.Context, ...option.ClientOption) (oauth2Service, error),
	listCryptoKeys listCryptoKeysFn) *Plugin {
	return &Plugin{
		entries: make(map[string]keyEntry),
		hooks: pluginHooks{
			newKMSClient:     newKMSClient,
			newOauth2Service: newOauth2Service,
			listCryptoKeys:   listCryptoKeys,
			clk:              clock.New(),
		},
		scheduleDestroy: make(chan *kmspb.CryptoKey, 120),
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
	config.serverID = serverID

	if config.KeyPolicyFile != "" {
		policyBytes, err := os.ReadFile(config.KeyPolicyFile)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to read file configured in 'key_policy_file': %v", err)
		}
		policyStr := string(policyBytes)
		config.keyPolicy = &policyStr
	}

	// Label values do not allow "." and have a maximum length of 63 characters.
	// https://cloud.google.com/kms/docs/creating-managing-labels#requirements
	// Hash the trust domain name to avoid restrictions.
	tdHash := sha1.Sum([]byte(req.CoreConfiguration.TrustDomain)) //nolint: gosec // We use sha1 to hash trust domain names in 128 bytes to avoid label restrictions

	var opts []option.ClientOption
	if config.ServiceAccountFile != "" {
		opts = append(opts, option.WithCredentialsFile(config.ServiceAccountFile))
	}
	oauth2Service, err := p.hooks.newOauth2Service(ctx, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create Google OAuth2 client: %v", err)
	}

	kc, err := p.hooks.newKMSClient(ctx, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create Google Cloud KMS client: %v", err)
	}

	config.tdHash = hex.EncodeToString(tdHash[:])
	fetcher := &keyFetcher{
		keyRing:        config.KeyRing,
		kmsClient:      kc,
		listCryptoKeys: p.hooks.listCryptoKeys,
		log:            p.log,
		serverID:       serverID,
		tdHash:         config.tdHash,
	}
	p.log.Debug("Fetching keys from Cloud KMS", "key_ring", config.KeyRing)
	keyEntries, err := fetcher.fetchKeyEntries(ctx)
	if err != nil {
		return nil, err
	}

	p.setCache(keyEntries)
	p.kmsClient = kc
	p.oauth2Service = oauth2Service

	// Cancel previous tasks in case of re configure.
	if p.cancelTasks != nil {
		p.cancelTasks()
	}

	p.configMtx.Lock()
	defer p.configMtx.Unlock()
	p.config = config

	// Start long-running tasks.
	ctx, p.cancelTasks = context.WithCancel(context.Background())
	go p.scheduleDestroyTask(ctx)
	go p.keepActiveCryptoKeysTask(ctx)
	go p.disposeCryptoKeysTask(ctx)

	return &configv1.ConfigureResponse{}, nil
}

// GenerateKey creates a key in KMS. If a key already exists in the local storage,
// it is updated.
func (p *Plugin) GenerateKey(ctx context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key ID is required")
	}
	if req.KeyType == keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE {
		return nil, status.Error(codes.InvalidArgument, "key type is required")
	}

	newKeyEntry, err := p.createKey(ctx, req.KeyId, req.KeyType)
	if err != nil {
		return nil, err
	}

	p.entriesMtx.Lock()
	defer p.entriesMtx.Unlock()
	if entry, ok := p.entries[req.KeyId]; ok {
		if err := p.enqueueDestruction(ctx, entry.cryptoKey); err != nil {
			p.log.Error("Failed to enqueue CryptoKeyVersion for destruction", reasonTag, err)
		}
	}

	p.entries[req.KeyId] = *newKeyEntry

	return &keymanagerv1.GenerateKeyResponse{
		PublicKey: newKeyEntry.publicKey,
	}, nil
}

// GetPublicKey returns the public key for a given key
func (p *Plugin) GetPublicKey(ctx context.Context, req *keymanagerv1.GetPublicKeyRequest) (*keymanagerv1.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key ID is required")
	}

	p.entriesMtx.RLock()
	defer p.entriesMtx.RUnlock()

	entry, ok := p.entries[req.KeyId]
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
		return nil, status.Error(codes.InvalidArgument, "key ID is required")
	}
	if req.SignerOpts == nil {
		return nil, status.Error(codes.InvalidArgument, "signer opts is required")
	}

	p.entriesMtx.RLock()
	defer p.entriesMtx.RUnlock()

	keyEntry, hasKey := p.entries[req.KeyId]
	if !hasKey {
		return nil, status.Errorf(codes.NotFound, "key %q not found", req.KeyId)
	}

	var (
		hashAlgo keymanagerv1.HashAlgorithm
		digest   *kmspb.Digest
	)
	switch opts := req.SignerOpts.(type) {
	case *keymanagerv1.SignDataRequest_HashAlgorithm:
		hashAlgo = opts.HashAlgorithm
	case *keymanagerv1.SignDataRequest_PssOptions:
		// RSASSA-PSS is not supported by this plugin.
		// See the comment in cryptoKeyVersionAlgorithmFromKeyType function for
		// more details.
		return nil, errors.New("the only RSA signature scheme supported is RSASSA-PKCS1-v1_5")
	default:
		return nil, fmt.Errorf("unsupported signer opts type %T", opts)
	}
	switch {
	case hashAlgo == keymanagerv1.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM:
		return nil, status.Error(codes.InvalidArgument, "hash algorithm is required")
	case hashAlgo == keymanagerv1.HashAlgorithm_SHA256:
		digest = &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{Sha256: req.Data},
		}
	case hashAlgo == keymanagerv1.HashAlgorithm_SHA384:
		digest = &kmspb.Digest{
			Digest: &kmspb.Digest_Sha384{Sha384: req.Data},
		}
	case hashAlgo == keymanagerv1.HashAlgorithm_SHA512:
		digest = &kmspb.Digest{
			Digest: &kmspb.Digest_Sha512{Sha512: req.Data},
		}
	default:
		return nil, status.Error(codes.InvalidArgument, "hash algorithm not supported")
	}

	signResp, err := p.kmsClient.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name:   keyEntry.cryptoKeyVersion.Name,
		Digest: digest,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to sign: %v", err)
	}

	return &keymanagerv1.SignDataResponse{
		Signature:      signResp.Signature,
		KeyFingerprint: keyEntry.publicKey.Fingerprint,
	}, nil
}

// createKey creates a new CryptoKey with a new CryptoKeyVersion.
// If there is a specified IAM policy through the KeyPolicyFile configuration,
// that policy is set to the created CryptoKey. If there is no IAM policy specified,
// a default policy is constructed and attached. This function requests Cloud KMS
// to get the public key of the created CryptoKeyVersion. A keyEntry is returned
// with the CryptoKey, CryptoKeyVersion and public key.
func (p *Plugin) createKey(ctx context.Context, spireKeyID string, keyType keymanagerv1.KeyType) (*keyEntry, error) {
	algorithm, err := cryptoKeyVersionAlgorithmFromKeyType(keyType)
	if err != nil {
		return nil, err
	}

	cryptoKeyID, err := generateCryptoKeyID(spireKeyID)
	if err != nil {
		return nil, fmt.Errorf("could not generate CryptoKeyID: %w", err)
	}

	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	cryptoKey, err := p.kmsClient.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		CryptoKey: &kmspb.CryptoKey{
			Labels:  p.getCryptoKeyLabels(config),
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: algorithm,
			},
		},
		CryptoKeyId: cryptoKeyID,
		Parent:      config.KeyRing,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create CryptoKey: %v", err)
	}

	log := p.log.With(cryptoKeyNameTag, cryptoKey.Name)
	log.Debug("CryptoKey created", algorithmTag, algorithm)

	if err := p.setIamPolicy(ctx, cryptoKey.Name); err != nil {
		p.log.With(cryptoKeyNameTag, cryptoKey.Name).Debug("Failed to set IAM policy")
		return nil, status.Errorf(codes.Internal, "failed to set IAM policy: %v", err)
	}

	cryptoKeyVersion, err := p.kmsClient.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{
		Name: cryptoKey.Name + "/cryptoKeyVersions/1",
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get CryptoKeyVersion: %v", err)
	}

	kmsPublicKey, err := p.kmsClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: cryptoKeyVersion.Name})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get public key: %v", err)
	}
	pemBlock, _ := pem.Decode([]byte(kmsPublicKey.Pem))

	return &keyEntry{
		cryptoKey:        cryptoKey,
		cryptoKeyVersion: cryptoKeyVersion,
		publicKey: &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    pemBlock.Bytes,
			Fingerprint: makeFingerprint(pemBlock.Bytes),
		},
	}, nil
}

// disposeCryptoKeys looks for active CryptoKeys that haven't been updated
// during the maxStaleDuration time window. Those keys are then enqueued for
// destruction.
func (p *Plugin) disposeCryptoKeys(ctx context.Context) error {
	p.log.Debug("Looking for CryptoKeys to dispose")

	config, err := p.getConfig()
	if err != nil {
		return err
	}
	it := p.hooks.listCryptoKeys(ctx, p.kmsClient, &kmspb.ListCryptoKeysRequest{
		Parent: config.KeyRing,
		Filter: p.getDisposeCryptoKeysFilter(config),
	})

	for {
		cryptoKey, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		switch {
		case err != nil:
			p.log.Error("Failure listing CryptoKeys to dispose", reasonTag, err)
			return err
		case cryptoKey == nil:
			p.log.Error("Failure listing CryptoKeys to dispose: nil response")
			return err
		}

		if err := p.enqueueDestruction(ctx, cryptoKey); err != nil {
			p.log.With(cryptoKeyNameTag, cryptoKey.Name).Error("Failed to enqueue CryptoKey for destruction", reasonTag, err)
		}
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

// enqueueDestruction enqueues the specified CryptoKey for destruction.
func (p *Plugin) enqueueDestruction(ctx context.Context, cryptoKey *kmspb.CryptoKey) (err error) {
	select {
	case p.scheduleDestroy <- cryptoKey:
		p.log.Debug("CryptoKey enqueued for destruction", cryptoKeyVersionNameTag, cryptoKey.Name)
	default:
		return fmt.Errorf("could not enqueue CryptoKey %q for destruction", cryptoKey.Name)
	}

	return nil
}

// getConfig gets the configuration of the plugin.
func (p *Plugin) getConfig() (*Config, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()

	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}

	return p.config, nil
}

// getCurrentIdentity gets the email of the authenticated service account that is
// interacting with the Cloud KMS Service.
func (p *Plugin) getCurrentIdentity(ctx context.Context) (email string, err error) {
	tokenInfo, err := p.oauth2Service.Tokeninfo().Do()
	if err != nil {
		return "", fmt.Errorf("could not get token information: %w", err)
	}

	return tokenInfo.Email, nil
}

// getDisposeCryptoKeysFilter gets the filter to be used to get the list of
// CryptoKeys that are stale but are still marked as active.
func (p *Plugin) getDisposeCryptoKeysFilter(config *Config) string {
	now := p.hooks.clk.Now()
	return "labels.spire-server-td = " + config.tdHash +
		" AND labels.spire-server-id != " + config.serverID +
		" AND labels.spire-active = true" +
		fmt.Sprintf(" AND labels.spire-last-update < %d", now.Add(-maxStaleDuration).Unix())
}

// getCryptoKeyLabels gets the labels that must be set to a new CryptoKey
// that is being created.
func (p *Plugin) getCryptoKeyLabels(config *Config) map[string]string {
	return map[string]string{
		"spire-server-td": config.tdHash,
		"spire-server-id": config.serverID,
		"spire-active":    "true",
	}
}

// setIamPolicy sets the IAM policy specified in the KeyPolicyFile to the given
// resource. If there is no KeyPolicyFile specified, a default policy is constructed
// and set to the resource.
func (p *Plugin) setIamPolicy(ctx context.Context, resource string) (err error) {
	config, err := p.getConfig()
	if err != nil {
		return err
	}
	log := p.log.With("resource", resource)

	// Get the policy of the created CryptoKey.
	h := p.kmsClient.ResourceIAM(resource)
	if h == nil {
		return status.Error(codes.Internal, "could not get Cloud KMS Handle")
	}

	// We use V3 for policies.
	h3 := h.V3()
	if h == nil {
		return status.Error(codes.Internal, "could not get Cloud KMS Handle3")
	}
	// Get the policy.
	policy, err := h3.Policy(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve IAM policy: %w", err)
	}

	// We expect the policy to be empty.
	if len(policy.Bindings) > 0 {
		// The policy is not empty, log the situation and do not replace it.
		log.Warn("The CryptoKey already has a policy. No policy will be set.", cryptoKeyNameTag, resource)
		return nil
	}
	if config.keyPolicy != nil {
		// There is a custom policy defined, parse it.
		customPolicy := &iam.Policy3{}
		err := json.Unmarshal([]byte(*config.keyPolicy), customPolicy)
		if err != nil {
			return fmt.Errorf("failed to parse JSON policy: %w", err)
		}
		policy = customPolicy
	} else {
		// No custom policy defined. Build the default policy.
		member, err := p.getCurrentIdentity(ctx)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to get current identity: %v", err)
		}
		policy.Bindings = []*iampb.Binding{
			{
				Role:    "roles/cloudkms.signerVerifier",
				Members: []string{fmt.Sprintf("serviceAccount:%s", member)},
			},
		}
	}
	err = h3.SetPolicy(ctx, policy)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to set IAM policy: %v", err)
	}

	log.Debug("IAM policy updated to use the default policy")
	return nil
}

// keepActiveCryptoKeys keeps CryptoKeys managed by this plugin active updating
// the spire-last-update label with the current Unix time.
func (p *Plugin) keepActiveCryptoKeys(ctx context.Context) error {
	p.log.Debug("Keeping CryptoKeys managed by this server active")

	p.entriesMtx.RLock()
	defer p.entriesMtx.RUnlock()
	var errs []string
	for _, entry := range p.entries {
		entry.cryptoKey.Labels["spire-last-update"] = fmt.Sprint(time.Now().Unix())
		_, err := p.kmsClient.UpdateCryptoKey(ctx, &kmspb.UpdateCryptoKeyRequest{
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"labels"},
			},
			CryptoKey: entry.cryptoKey,
		})
		if err != nil {
			p.log.Error("Failed to update CryptoKey", cryptoKeyVersionNameTag, entry.cryptoKeyVersion.Name, reasonTag, err)
			errs = append(errs, err.Error())
		}
	}

	if errs != nil {
		return fmt.Errorf(strings.Join(errs, ": "))
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

func (p *Plugin) notifyDestroy(err error) {
	if p.hooks.scheduleDestroySignal != nil {
		p.hooks.scheduleDestroySignal <- err
	}
}

func (p *Plugin) notifyDisposeCryptoKeys(err error) {
	if p.hooks.disposeKeysSignal != nil {
		p.hooks.disposeKeysSignal <- err
	}
}

func (p *Plugin) notifyKeepActiveCryptoKeys(err error) {
	if p.hooks.keepActiveCryptoKeysSignal != nil {
		p.hooks.keepActiveCryptoKeysSignal <- err
	}
}

// scheduleDestroyTask ia a long running task that schedules the destruction
// of inactive CryptoKeyVersions and sets the corresponding CryptoKey as inactive.
func (p *Plugin) scheduleDestroyTask(ctx context.Context) {
	backoffMin := 1 * time.Second
	backoffMax := 60 * time.Second
	backoff := backoffMin

	for {
		select {
		case <-ctx.Done():
			return
		case cryptoKey := <-p.scheduleDestroy:
			cryptoKeyVersionName := getFirstCryptoKeyVersionName(cryptoKey.Name)
			log := p.log.With(cryptoKeyNameTag, cryptoKey.Name, cryptoKeyVersionNameTag, cryptoKeyVersionName)
			destroyedCryptoKeyVersion, err := p.kmsClient.DestroyCryptoKeyVersion(ctx, &kmspb.DestroyCryptoKeyVersionRequest{
				Name: cryptoKeyVersionName,
			})
			switch status.Code(err) {
			case codes.NotFound:
				// CryptoKeyVersion is not found, no CryptoKeyVersion to destroy
				log.Warn("CryptoKeyVersion not found")
				p.setInactive(ctx, cryptoKey)
				backoff = backoffMin
				p.notifyDestroy(err)
				continue
			case codes.OK:
				log.Debug("CryptoKeyVersion scheduled for destruction", "destroy_time", destroyedCryptoKeyVersion.DestroyTime.AsTime())
				p.setInactive(ctx, cryptoKey)
				backoff = backoffMin
				p.notifyDestroy(nil)
				continue
			default:
				log.Error("It was not possible to schedule CryptoKeyVersion for destruction", reasonTag, err)

				// There was an error in the DestroyCryptoKeyVersion call.
				// Try to get the CryptoKeyVersion to know the state of the
				// CryptoKeyVersion and if we need to re-enqueue.
				cryptoKeyVersion, err := p.kmsClient.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{
					Name: cryptoKeyVersionName,
				})
				switch status.Code(err) {
				case codes.NotFound:
					// Purely defensive. We don't really expect this situation,
					// because this should have been captured during the
					// DestroyCryptoKeyVersion call that was just performed.
					log.Warn("CryptoKeyVersion not found")
					p.setInactive(ctx, cryptoKey)
					backoff = backoffMin
					p.notifyDestroy(err)
					continue
				case codes.OK:
					if cryptoKeyVersion.State != kmspb.CryptoKeyVersion_ENABLED {
						// Something external to the plugin modified the state
						// of the CryptoKeyVersion. Do not try to schedule it for
						// destruction.
						log.Warn("CryptoKeyVersion is not enabled, will not be scheduled for destruction", "crypto_key_version_state", cryptoKeyVersion.State.String())
						p.setInactive(ctx, cryptoKey)
						backoff = backoffMin
						p.notifyDestroy(err)
						continue
					}
				default:
					// The GetCryptoKeyVersion call failed. Log this and re-enqueue
					// the CryptoKey for destruction. Hopefully, this is a
					// recoverable error.
					log.Error("Could not get the CryptoKeyVersion while trying to schedule it for destruction")
				}

				select {
				case p.scheduleDestroy <- cryptoKey:
					log.Debug("CryptoKeyVersion re-enqueued for destruction")
				default:
					log.Error("Failed to re-enqueue CryptoKeyVersion for destruction")
				}
			}
			p.notifyDestroy(err)
			backoff = min(backoff*2, backoffMax)
			p.hooks.clk.Sleep(backoff)
		}
	}
}

// setInactive updates the spire-active label in the specified CryptoKey to
// indicate that is inactive.
func (p *Plugin) setInactive(ctx context.Context, cryptoKey *kmspb.CryptoKey) {
	log := p.log.With(cryptoKeyNameTag, cryptoKey.Name)

	cryptoKey.Labels["spire-active"] = "false"
	_, err := p.kmsClient.UpdateCryptoKey(ctx, &kmspb.UpdateCryptoKeyRequest{
		UpdateMask: &fieldmaskpb.FieldMask{
			Paths: []string{"labels"},
		},
		CryptoKey: cryptoKey,
	})
	if err != nil {
		log.Error("Could not update CryptoKey as incactive", reasonTag, err)
	}

	log.Debug("CryptoKey updated as inactive", cryptoKeyNameTag, cryptoKey.Name)
}

// setCache sets the cached entries with the provided entries.
func (p *Plugin) setCache(keyEntries []*keyEntry) {
	p.entriesMtx.Lock()
	defer p.entriesMtx.Unlock()

	p.entries = make(map[string]keyEntry)

	for _, e := range keyEntries {
		p.entries[e.publicKey.Id] = *e
		p.log.Debug("Cloud KMS key loaded", cryptoKeyVersionNameTag, e.cryptoKeyVersion.Name, algorithmTag, e.cryptoKeyVersion.Algorithm)
	}
}

// createServerID creates a randomly generated UUID to be used as a server ID
// and stores it in the specified idPath.
func createServerID(idPath string) (string, error) {
	id, err := generateUniqueID()
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to generate ID for server: %v", err)
	}

	err = os.WriteFile(idPath, []byte(id), 0600)
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
func generateCryptoKeyID(spireKeyID string) (cryptoKeyID string, err error) {
	uniqueID, err := generateUniqueID()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("spire-key-%s-%s", uniqueID, spireKeyID), nil
}

// generateUniqueID returns a randomly generated UUID.
func generateUniqueID() (id string, err error) {
	u, err := uuid.NewV4()
	if err != nil {
		return "", status.Errorf(codes.Internal, "could not create a randomly generated UUID: %v", err)
	}

	return u.String(), nil
}

// getFirstCryptoKeyVersionName returns the first CryptoKeyVersion corresponding
// to the provided CryptoKeyName.
func getFirstCryptoKeyVersionName(cryptoKeyName string) string {
	return fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName)
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

func makeFingerprint(pkixData []byte) string {
	s := sha256.Sum256(pkixData)
	return hex.EncodeToString(s[:])
}

// min returns the minimum of the provided time durations.
func min(x, y time.Duration) time.Duration {
	if x < y {
		return x
	}
	return y
}

// parseAndValidateConfig returns an error if any configuration provided does
// not meet acceptable criteria
func parseAndValidateConfig(c string) (*Config, error) {
	config := new(Config)

	if err := hcl.Decode(config, c); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if config.KeyRing == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is missing the key ring")
	}

	if config.KeyMetadataFile == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is missing server ID file path")
	}

	return config, nil
}
