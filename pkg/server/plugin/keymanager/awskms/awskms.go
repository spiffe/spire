package awskms

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName       = "awskms"
	aliasPrefix      = "alias/"
	defaultKeyPrefix = "SPIRE_SERVER_KEY/"

	keyIDTag = "key_id"
	aliasTag = "alias"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, keymanager.PluginServer(p))
}

type keyEntry struct {
	KMSKeyID  string
	Alias     string
	PublicKey *keymanager.PublicKey
}

type pluginHooks struct {
	newClient func(ctx context.Context, config *Config) (kmsClient, error)
}

// Plugin is the main representation of this keymanager plugin
type Plugin struct {
	keymanager.UnsafeKeyManagerServer
	log                  hclog.Logger
	mu                   sync.RWMutex
	entries              map[string]keyEntry
	kmsClient            kmsClient
	keyPrefix            string
	scheduleDelete       chan string
	cancelScheduleDelete context.CancelFunc
	hooks                pluginHooks
}

// Config provides configuration context for the plugin
type Config struct {
	AccessKeyID     string `hcl:"access_key_id" json:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key" json:"secret_access_key"`
	Region          string `hcl:"region" json:"region"`
	KeyPrefix       string `hcl:"key_prefix" json:"key_prefix"`
}

// New returns an instantiated plugin
func New() *Plugin {
	return newPlugin(newKMSClient)
}

func newPlugin(newClient func(ctx context.Context, config *Config) (kmsClient, error)) *Plugin {
	return &Plugin{
		entries: make(map[string]keyEntry),
		hooks: pluginHooks{
			newClient: newClient,
		},
		scheduleDelete: make(chan string, 120),
	}
}

// SetLogger sets a logger
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Configure sets up the plugin
func (p *Plugin) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	// cancels previous schedule delete task in case of re configure
	if p.cancelScheduleDelete != nil {
		p.cancelScheduleDelete()
	}

	config, err := validateConfig(req.Configuration)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.keyPrefix = config.KeyPrefix
	p.kmsClient, err = p.hooks.newClient(ctx, config)
	if err != nil {
		return nil, newErrorf(codes.Internal, "failed to create KMS client: %v", err)
	}

	p.log.Debug("Fetching key aliases from KMS")
	err = p.buildCache(ctx)
	if err != nil {
		return nil, err
	}

	ctx, p.cancelScheduleDelete = context.WithCancel(context.Background())
	go p.scheduleDeleteTask(ctx)

	return &plugin.ConfigureResponse{}, nil
}

// GenerateKey creates a key in KMS. If a key already exists in the local storage, it is updated.
func (p *Plugin) GenerateKey(ctx context.Context, req *keymanager.GenerateKeyRequest) (*keymanager.GenerateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, newError(codes.InvalidArgument, "key id is required")
	}
	if req.KeyType == keymanager.KeyType_UNSPECIFIED_KEY_TYPE {
		return nil, newError(codes.InvalidArgument, "key type is required")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	spireKeyID := req.KeyId
	newEntry, err := p.createKey(ctx, spireKeyID, req.KeyType)
	if err != nil {
		return nil, err
	}

	p.log.Debug("Key created", keyIDTag, newEntry.KMSKeyID)
	oldEntry, hasOldEntry := p.entries[spireKeyID]

	if !hasOldEntry {
		//create alias
		_, err = p.kmsClient.CreateAlias(ctx, &kms.CreateAliasInput{
			AliasName:   aws.String(newEntry.Alias),
			TargetKeyId: &newEntry.KMSKeyID,
		})
		if err != nil {
			return nil, newErrorf(codes.Internal, "failed to create alias: %v", err)
		}
		p.log.Debug("Alias created", aliasTag, newEntry.Alias)
	} else {
		//update alias
		_, err = p.kmsClient.UpdateAlias(ctx, &kms.UpdateAliasInput{
			AliasName:   aws.String(newEntry.Alias),
			TargetKeyId: &newEntry.KMSKeyID,
		})
		if err != nil {
			return nil, newErrorf(codes.Internal, "failed to update alias: %v", err)
		}
		p.log.Debug("Alias updated", aliasTag, newEntry.Alias)

		p.scheduleDelete <- oldEntry.KMSKeyID
	}

	err = p.setEntry(spireKeyID, newEntry)
	if err != nil {
		return nil, newError(codes.Internal, err.Error())
	}

	return &keymanager.GenerateKeyResponse{
		PublicKey: newEntry.PublicKey,
	}, nil
}

// SignData creates a digital signature for the data to be signed
func (p *Plugin) SignData(ctx context.Context, req *keymanager.SignDataRequest) (*keymanager.SignDataResponse, error) {
	if req.KeyId == "" {
		return nil, newError(codes.InvalidArgument, "key id is required")
	}
	if req.SignerOpts == nil {
		return nil, newError(codes.InvalidArgument, "signer opts is required")
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	keyEntry, hasKey := p.entries[req.KeyId]
	if !hasKey {
		return nil, newErrorf(codes.NotFound, "no such key %q", req.KeyId)
	}

	signingAlgo, err := signingAlgorithmForKMS(keyEntry.PublicKey.Type, req.SignerOpts)
	if err != nil {
		return nil, newError(codes.InvalidArgument, err.Error())
	}

	signResp, err := p.kmsClient.Sign(ctx, &kms.SignInput{
		KeyId:            &keyEntry.Alias,
		Message:          req.Data,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: signingAlgo,
	})
	if err != nil {
		return nil, newErrorf(codes.Internal, "failed to sign: %v", err)
	}

	return &keymanager.SignDataResponse{Signature: signResp.Signature}, nil
}

// GetPublicKey returns the public key for a given key
func (p *Plugin) GetPublicKey(ctx context.Context, req *keymanager.GetPublicKeyRequest) (*keymanager.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, newError(codes.InvalidArgument, "key id is required")
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.entries[req.KeyId]
	if !ok {
		return nil, newErrorf(codes.NotFound, "no such key %q", req.KeyId)
	}

	return &keymanager.GetPublicKeyResponse{
		PublicKey: entry.PublicKey,
	}, nil
}

// GetPublicKeys return the publicKey for all the keys
func (p *Plugin) GetPublicKeys(context.Context, *keymanager.GetPublicKeysRequest) (*keymanager.GetPublicKeysResponse, error) {
	var keys []*keymanager.PublicKey
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, key := range p.entries {
		keys = append(keys, key.PublicKey)
	}

	return &keymanager.GetPublicKeysResponse{PublicKeys: keys}, nil
}

// GetPluginInfo returns information about this plugin
func (p *Plugin) GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}

func (p *Plugin) setEntry(spireKeyID string, entry keyEntry) error {
	if spireKeyID == "" {
		return errors.New("spire key id is required")
	}
	if entry.KMSKeyID == "" {
		return fmt.Errorf("kms key id missing for SPIRE key id %q", spireKeyID)
	}
	if entry.Alias == "" {
		return errors.New("alias is required")
	}
	if entry.PublicKey == nil {
		return errors.New("public key is required")
	}
	if entry.PublicKey.Id == "" {
		return errors.New("public key id is required")
	}
	if entry.PublicKey.Type == keymanager.KeyType_UNSPECIFIED_KEY_TYPE {
		return errors.New("public key type is required")
	}
	if entry.PublicKey.PkixData == nil || len(entry.PublicKey.PkixData) == 0 {
		return errors.New("public key pkix data is required")
	}

	p.entries[spireKeyID] = entry
	return nil
}

func (p *Plugin) createKey(ctx context.Context, spireKeyID string, keyType keymanager.KeyType) (keyEntry, error) {
	res := keyEntry{}
	description := p.descriptionFromSpireKeyID(spireKeyID)
	keySpec, ok := keySpecFromKeyType(keyType)
	if !ok {
		return res, newErrorf(codes.Internal, "unsupported key type: %v", keyType)
	}

	createKeyInput := &kms.CreateKeyInput{
		Description:           aws.String(description),
		KeyUsage:              types.KeyUsageTypeSignVerify,
		CustomerMasterKeySpec: keySpec,
	}

	key, err := p.kmsClient.CreateKey(ctx, createKeyInput)
	if err != nil {
		return res, newErrorf(codes.Internal, "failed to create key: %v", err)
	}

	pub, err := p.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: key.KeyMetadata.KeyId})
	if err != nil {
		return res, newErrorf(codes.Internal, "failed to get public key: %v", err)
	}

	return keyEntry{
		KMSKeyID: *pub.KeyId,
		Alias:    p.aliasFromSpireKeyID(spireKeyID),
		PublicKey: &keymanager.PublicKey{
			Id:       spireKeyID,
			Type:     keyType,
			PkixData: pub.PublicKey,
		},
	}, nil
}

func (p *Plugin) fetchKeyEntry(ctx context.Context, aliasName string, spireKeyID string) (*keyEntry, error) {
	describeResp, err := p.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &aliasName})
	if err != nil {
		return nil, newErrorf(codes.Internal, "failed to describe key: %v", err)
	}

	if !describeResp.KeyMetadata.Enabled {
		// this means something external to the plugin, deleted or disabled the key without removing the alias
		// returning an error provides the opportunity or reverting this in KMS
		return nil, newErrorf(codes.FailedPrecondition, "found disabled SPIRE key: %q, alias: %q", *describeResp.KeyMetadata.KeyId, aliasName)
	}

	if describeResp.KeyMetadata.KeyId == nil {
		return nil, newErrorf(codes.FailedPrecondition, "found SPIRE alias without key: %q", aliasName)
	}

	keyType, ok := keyTypeFromKeySpec(describeResp.KeyMetadata.CustomerMasterKeySpec)
	if !ok {
		return nil, newErrorf(codes.Internal, "unsupported key spec: %v", describeResp.KeyMetadata.CustomerMasterKeySpec)
	}

	getPublicKeyResp, err := p.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &aliasName})
	if err != nil {
		return nil, newErrorf(codes.Internal, "failed to get public key: %v", err)
	}

	return &keyEntry{
		KMSKeyID: *describeResp.KeyMetadata.KeyId,
		Alias:    aliasName,
		PublicKey: &keymanager.PublicKey{
			Id:       spireKeyID,
			Type:     keyType,
			PkixData: getPublicKeyResp.PublicKey,
		},
	}, err
}

func (p *Plugin) fetchAliasesPages(ctx context.Context) ([]*keyEntry, error) {
	var keyEntries []*keyEntry
	keyEntriesMutex := &sync.Mutex{}
	paginator := kms.NewListAliasesPaginator(p.kmsClient, &kms.ListAliasesInput{})
	g, ctx := errgroup.WithContext(ctx)

	for {
		aliasesResp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, newErrorf(codes.Internal, "failed to build cache of KMS keys: failed to fetch keys: %v", err)
		}
		p.log.Debug("Found aliases", "num_aliases", len(aliasesResp.Aliases))

		for _, alias := range aliasesResp.Aliases {
			spireKeyID, ok := p.spireKeyIDFromAlias(alias)
			if !ok {
				continue
			}
			if alias.TargetKeyId == nil {
				// this means something external to the plugin created the alias, without associating it to a key.
				// it should never happen with CMKs.
				return nil, newErrorf(codes.FailedPrecondition, "failed to build cache of KMS keys: found SPIRE alias without key: %q", *alias.AliasName)
			}

			aliasName := *alias.AliasName
			g.Go(func() error {
				entry, err := p.fetchKeyEntry(ctx, aliasName, spireKeyID)
				if err != nil {
					return err
				}
				keyEntriesMutex.Lock()
				keyEntries = append(keyEntries, entry)
				keyEntriesMutex.Unlock()
				return nil
			})
		}

		if !paginator.HasMorePages() {
			break
		}
	}

	if err := g.Wait(); err != nil {
		statusErr := status.Convert(err)
		return nil, newErrorf(statusErr.Code(), "failed to build cache of KMS keys: %v", statusErr.Message())
	}

	return keyEntries, nil
}

// buildCache gets all aliases from KMS and builds an in memory representation with the ones that belong to the current server
// for each key that belongs to the server we will trigger a gouroutine that gets the extra information
func (p *Plugin) buildCache(ctx context.Context) error {
	keyEntries, err := p.fetchAliasesPages(ctx)
	if err != nil {
		return err
	}

	//add results to cache
	for _, e := range keyEntries {
		err := p.setEntry(e.PublicKey.Id, *e)
		if err != nil {
			return newError(codes.Internal, err.Error())
		}
		p.log.Debug("Key loaded", keyIDTag, e.KMSKeyID, aliasTag, e.Alias)
	}

	return nil
}

// scheduleDeleteTask ia a long running task that deletes keys that were rotated
func (p *Plugin) scheduleDeleteTask(ctx context.Context) {
	backoffMin := 1 * time.Second
	backoffMax := 60 * time.Second
	backoff := backoffMin

	for {
		select {
		case <-ctx.Done():
			p.log.Debug("Stopping schedule delete task", "reason", ctx.Err())
			return
		case keyID := <-p.scheduleDelete:
			log := p.log.With(keyIDTag, keyID)
			_, err := p.kmsClient.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
				KeyId:               aws.String(keyID),
				PendingWindowInDays: aws.Int32(7),
			})

			if err == nil {
				log.Debug("Key deleted")
				backoff = backoffMin
				continue
			}

			var notFoundErr *types.NotFoundException
			if errors.As(err, &notFoundErr) {
				log.Error("No such key, dropping from delete schedule")
				continue
			}

			var invalidArnErr *types.InvalidArnException
			if errors.As(err, &invalidArnErr) {
				log.Error("Invalid ARN, dropping from delete schedule")
				continue
			}

			log.Error("It was not possible to schedule key for deletion", "reason", err)
			p.scheduleDelete <- keyID
			backoff = min(backoff*2, backoffMax)
			time.Sleep(backoff)
		}
	}
}

func (p *Plugin) spireKeyIDFromAlias(alias types.AliasListEntry) (string, bool) {
	if alias.AliasName == nil {
		p.log.Warn("Found alias without a name")
		return "", false
	}

	prefix := aliasPrefix + p.keyPrefix
	if !strings.HasPrefix(*alias.AliasName, prefix) {
		return "", false
	}
	return strings.TrimPrefix(*alias.AliasName, prefix), true
}

func (p *Plugin) aliasFromSpireKeyID(spireKeyID string) string {
	return aliasPrefix + p.keyPrefix + spireKeyID
}

func (p *Plugin) descriptionFromSpireKeyID(spireKeyID string) string {
	return p.keyPrefix + spireKeyID
}

// validateConfig returns an error if any configuration provided does not meet acceptable criteria
func validateConfig(c string) (*Config, error) {
	config := new(Config)

	if err := hcl.Decode(config, c); err != nil {
		return nil, newErrorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if config.Region == "" {
		return nil, newError(codes.InvalidArgument, "configuration is missing a region")
	}

	if config.KeyPrefix == "" {
		config.KeyPrefix = defaultKeyPrefix
	}

	return config, nil
}

func signingAlgorithmForKMS(keyType keymanager.KeyType, signerOpts interface{}) (types.SigningAlgorithmSpec, error) {
	var (
		hashAlgo keymanager.HashAlgorithm
		isPSS    bool
	)

	switch opts := signerOpts.(type) {
	case *keymanager.SignDataRequest_HashAlgorithm:
		hashAlgo = opts.HashAlgorithm
		isPSS = false
	case *keymanager.SignDataRequest_PssOptions:
		if opts.PssOptions == nil {
			return "", errors.New("PSS options are required")
		}
		hashAlgo = opts.PssOptions.HashAlgorithm
		isPSS = true
		// opts.PssOptions.SaltLength is handled by KMS. The salt length matches the bits of the hashing algorithm.
	default:
		return "", fmt.Errorf("unsupported signer opts type %T", opts)
	}

	isRSA := keyType == keymanager.KeyType_RSA_2048 || keyType == keymanager.KeyType_RSA_4096

	switch {
	case hashAlgo == keymanager.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM:
		return "", errors.New("hash algorithm is required")
	case keyType == keymanager.KeyType_EC_P256 && hashAlgo == keymanager.HashAlgorithm_SHA256:
		return types.SigningAlgorithmSpecEcdsaSha256, nil
	case keyType == keymanager.KeyType_EC_P384 && hashAlgo == keymanager.HashAlgorithm_SHA384:
		return types.SigningAlgorithmSpecEcdsaSha384, nil
	case isRSA && !isPSS && hashAlgo == keymanager.HashAlgorithm_SHA256:
		return types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
	case isRSA && !isPSS && hashAlgo == keymanager.HashAlgorithm_SHA384:
		return types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
	case isRSA && !isPSS && hashAlgo == keymanager.HashAlgorithm_SHA512:
		return types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
	case isRSA && isPSS && hashAlgo == keymanager.HashAlgorithm_SHA256:
		return types.SigningAlgorithmSpecRsassaPssSha256, nil
	case isRSA && isPSS && hashAlgo == keymanager.HashAlgorithm_SHA384:
		return types.SigningAlgorithmSpecRsassaPssSha384, nil
	case isRSA && isPSS && hashAlgo == keymanager.HashAlgorithm_SHA512:
		return types.SigningAlgorithmSpecRsassaPssSha512, nil
	default:
		return "", fmt.Errorf("unsupported combination of keytype: %v and hashing algorithm: %v", keyType, hashAlgo)
	}
}

func keyTypeFromKeySpec(keySpec types.CustomerMasterKeySpec) (keymanager.KeyType, bool) {
	switch keySpec {
	case types.CustomerMasterKeySpecRsa2048:
		return keymanager.KeyType_RSA_2048, true
	case types.CustomerMasterKeySpecRsa4096:
		return keymanager.KeyType_RSA_4096, true
	case types.CustomerMasterKeySpecEccNistP256:
		return keymanager.KeyType_EC_P256, true
	case types.CustomerMasterKeySpecEccNistP384:
		return keymanager.KeyType_EC_P384, true
	default:
		return keymanager.KeyType_UNSPECIFIED_KEY_TYPE, false
	}
}

func keySpecFromKeyType(keyType keymanager.KeyType) (types.CustomerMasterKeySpec, bool) {
	switch keyType {
	case keymanager.KeyType_RSA_2048:
		return types.CustomerMasterKeySpecRsa2048, true
	case keymanager.KeyType_RSA_4096:
		return types.CustomerMasterKeySpecRsa4096, true
	case keymanager.KeyType_EC_P256:
		return types.CustomerMasterKeySpecEccNistP256, true
	case keymanager.KeyType_EC_P384:
		return types.CustomerMasterKeySpecEccNistP384, true
	default:
		return "", false
	}
}

func newError(code codes.Code, msg string) error {
	return status.Error(code, pluginName+": "+msg)
}

func newErrorf(code codes.Code, format string, args ...interface{}) error {
	return status.Error(code, pluginName+": "+fmt.Sprintf(format, args...))
}

func min(x, y time.Duration) time.Duration {
	if x < y {
		return x
	}
	return y
}
