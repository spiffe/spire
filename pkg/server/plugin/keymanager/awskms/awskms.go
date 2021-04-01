package awskms

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/gofrs/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	keymanagerv0 "github.com/spiffe/spire/proto/spire/server/keymanager/v0"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName  = "aws_kms"
	aliasPrefix = "alias/SPIRE_SERVER/"

	keyArnTag    = "key_arn"
	aliasNameTag = "alias_name"
	reasonTag    = "reason"

	refreshAliasesFrequency = time.Hour * 6
	disposeAliasesFrequency = time.Hour * 24
	aliasThreshold          = time.Hour * 48

	disposeKeysFrequency = time.Hour * 48
	keyThreshold         = time.Hour * 48
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, keymanagerv0.PluginServer(p))
}

type keyEntry struct {
	Arn       string
	AliasName string
	PublicKey *keymanagerv0.PublicKey
}

type pluginHooks struct {
	newClient func(ctx context.Context, config *Config) (kmsClient, error)
	clk       clock.Clock
	// just for testing
	scheduleDeleteSignal chan error
	refreshAliasesSignal chan error
	disposeAliasesSignal chan error
	disposeKeysSignal    chan error
}

// Plugin is the main representation of this keymanager plugin
type Plugin struct {
	keymanagerv0.UnsafeKeyManagerServer
	log            hclog.Logger
	mu             sync.RWMutex
	entries        map[string]keyEntry
	kmsClient      kmsClient
	trustDomain    string
	serverID       string
	scheduleDelete chan string
	cancelTasks    context.CancelFunc
	hooks          pluginHooks
}

// Config provides configuration context for the plugin
type Config struct {
	AccessKeyID      string `hcl:"access_key_id" json:"access_key_id"`
	SecretAccessKey  string `hcl:"secret_access_key" json:"secret_access_key"`
	Region           string `hcl:"region" json:"region"`
	ServerIDFilePath string `hcl:"server_id_file_path" json:"server_id_file_path"`
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
			clk:       clock.New(),
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
	config, err := parseAndValidateConfig(req.Configuration)
	if err != nil {
		return nil, err
	}

	serverID, err := loadServerID(config.ServerIDFilePath)
	if err != nil {
		return nil, err
	}
	p.log.Debug("Loaded server id", "server_id", serverID)

	kc, err := p.hooks.newClient(ctx, config)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create KMS client: %v", err)
	}

	fetcher := &keyFetcher{
		log:         p.log,
		kmsClient:   kc,
		serverID:    serverID,
		trustDomain: req.GlobalConfig.TrustDomain,
	}
	p.log.Debug("Fetching key aliases from KMS")
	keyEntries, err := fetcher.fetchKeyEntries(ctx)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.setCache(keyEntries)
	p.kmsClient = kc
	p.trustDomain = req.GlobalConfig.TrustDomain
	p.serverID = serverID

	// cancels previous tasks in case of re configure
	if p.cancelTasks != nil {
		p.cancelTasks()
	}

	// start tasks
	ctx, p.cancelTasks = context.WithCancel(context.Background())
	go p.scheduleDeleteTask(ctx)
	go p.refreshAliasesTask(ctx)
	go p.disposeAliasesTask(ctx)
	go p.disposeKeysTask(ctx)

	return &plugin.ConfigureResponse{}, nil
}

// GenerateKey creates a key in KMS. If a key already exists in the local storage, it is updated.
func (p *Plugin) GenerateKey(ctx context.Context, req *keymanagerv0.GenerateKeyRequest) (*keymanagerv0.GenerateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.KeyType == keymanagerv0.KeyType_UNSPECIFIED_KEY_TYPE {
		return nil, status.Error(codes.InvalidArgument, "key type is required")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	spireKeyID := req.KeyId
	newKeyEntry, err := p.createKey(ctx, spireKeyID, req.KeyType)
	if err != nil {
		return nil, err
	}

	err = p.assignAlias(ctx, newKeyEntry)
	if err != nil {
		return nil, err
	}

	p.entries[spireKeyID] = *newKeyEntry

	return &keymanagerv0.GenerateKeyResponse{
		PublicKey: newKeyEntry.PublicKey,
	}, nil
}

// SignData creates a digital signature for the data to be signed
func (p *Plugin) SignData(ctx context.Context, req *keymanagerv0.SignDataRequest) (*keymanagerv0.SignDataResponse, error) {
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
		return nil, status.Errorf(codes.NotFound, "no such key %q", req.KeyId)
	}

	signingAlgo, err := signingAlgorithmForKMS(keyEntry.PublicKey.Type, req.SignerOpts)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	signResp, err := p.kmsClient.Sign(ctx, &kms.SignInput{
		KeyId:            &keyEntry.Arn,
		Message:          req.Data,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: signingAlgo,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to sign: %v", err)
	}

	return &keymanagerv0.SignDataResponse{Signature: signResp.Signature}, nil
}

// GetPublicKey returns the public key for a given key
func (p *Plugin) GetPublicKey(ctx context.Context, req *keymanagerv0.GetPublicKeyRequest) (*keymanagerv0.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.entries[req.KeyId]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no such key %q", req.KeyId)
	}

	return &keymanagerv0.GetPublicKeyResponse{
		PublicKey: entry.PublicKey,
	}, nil
}

// GetPublicKeys return the publicKey for all the keys
func (p *Plugin) GetPublicKeys(context.Context, *keymanagerv0.GetPublicKeysRequest) (*keymanagerv0.GetPublicKeysResponse, error) {
	var keys []*keymanagerv0.PublicKey
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, key := range p.entries {
		keys = append(keys, key.PublicKey)
	}

	return &keymanagerv0.GetPublicKeysResponse{PublicKeys: keys}, nil
}

// GetPluginInfo returns information about this plugin
func (p *Plugin) GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}

func (p *Plugin) createKey(ctx context.Context, spireKeyID string, keyType keymanagerv0.KeyType) (*keyEntry, error) {
	description := p.descriptionFromSpireKeyID(spireKeyID)
	keySpec, ok := keySpecFromKeyType(keyType)
	if !ok {
		return nil, status.Errorf(codes.Internal, "unsupported key type: %v", keyType)
	}

	createKeyInput := &kms.CreateKeyInput{
		Description:           aws.String(description),
		KeyUsage:              types.KeyUsageTypeSignVerify,
		CustomerMasterKeySpec: keySpec,
	}

	key, err := p.kmsClient.CreateKey(ctx, createKeyInput)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create key: %v", err)
	}
	if key == nil || key.KeyMetadata == nil || key.KeyMetadata.Arn == nil {
		return nil, status.Error(codes.Internal, "malformed create key response")
	}
	p.log.Debug("Key created", keyArnTag, *key.KeyMetadata.Arn)

	pub, err := p.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: key.KeyMetadata.Arn})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get public key: %v", err)
	}
	if pub == nil || pub.KeyId == nil || pub.PublicKey == nil || len(pub.PublicKey) == 0 {
		return nil, status.Error(codes.Internal, "malformed get public key response")
	}

	return &keyEntry{
		Arn:       *key.KeyMetadata.Arn,
		AliasName: p.aliasFromSpireKeyID(spireKeyID),
		PublicKey: &keymanagerv0.PublicKey{
			Id:       spireKeyID,
			Type:     keyType,
			PkixData: pub.PublicKey,
		},
	}, nil
}

func (p *Plugin) assignAlias(ctx context.Context, entry *keyEntry) error {
	oldEntry, hasOldEntry := p.entries[entry.PublicKey.Id]

	if !hasOldEntry {
		// create alias
		_, err := p.kmsClient.CreateAlias(ctx, &kms.CreateAliasInput{
			AliasName:   aws.String(entry.AliasName),
			TargetKeyId: &entry.Arn,
		})
		if err != nil {
			return status.Errorf(codes.Internal, "failed to create alias: %v", err)
		}
		p.log.Debug("Alias created", aliasNameTag, entry.AliasName, keyArnTag, entry.Arn)
	} else {
		// update alias
		_, err := p.kmsClient.UpdateAlias(ctx, &kms.UpdateAliasInput{
			AliasName:   aws.String(entry.AliasName),
			TargetKeyId: &entry.Arn,
		})
		if err != nil {
			return status.Errorf(codes.Internal, "failed to update alias: %v", err)
		}
		p.log.Debug("Alias updated", aliasNameTag, entry.AliasName, keyArnTag, entry.Arn)

		select {
		case p.scheduleDelete <- oldEntry.Arn:
			p.log.Debug("Key enqueued for deletion", keyArnTag, oldEntry.Arn)
		default:
			p.log.Error("Failed to enqueue key for deletion", keyArnTag, oldEntry.Arn)
		}
	}
	return nil
}

func (p *Plugin) setCache(keyEntries []*keyEntry) {
	// clean previous cache
	p.entries = make(map[string]keyEntry)

	// add results to cache
	for _, e := range keyEntries {
		p.entries[e.PublicKey.Id] = *e
		p.log.Debug("Key loaded", keyArnTag, e.Arn, aliasNameTag, e.AliasName)
	}
}

// scheduleDeleteTask ia a long running task that deletes keys that were rotated
func (p *Plugin) scheduleDeleteTask(ctx context.Context) {
	backoffMin := 1 * time.Second
	backoffMax := 60 * time.Second
	backoff := backoffMin

	for {
		select {
		case <-ctx.Done():
			return
		case keyArn := <-p.scheduleDelete:
			log := p.log.With(keyArnTag, keyArn)
			_, err := p.kmsClient.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
				KeyId:               aws.String(keyArn),
				PendingWindowInDays: aws.Int32(7),
			})

			if err == nil {
				log.Debug("Key deleted")
				backoff = backoffMin
				p.notifyDelete(nil)
				continue
			}

			var notFoundErr *types.NotFoundException
			if errors.As(err, &notFoundErr) {
				log.Error("No such key, dropping from delete schedule")
				p.notifyDelete(err)
				continue
			}

			var invalidArnErr *types.InvalidArnException
			if errors.As(err, &invalidArnErr) {
				log.Error("Invalid ARN, dropping from delete schedule")
				p.notifyDelete(err)
				continue
			}

			var invalidState *types.KMSInvalidStateException
			if errors.As(err, &invalidState) {
				log.Error("Key was on invalid state for deletion, dropping from delete schedule")
				p.notifyDelete(err)
				continue
			}

			log.Error("It was not possible to schedule key for deletion", reasonTag, err)
			select {
			case p.scheduleDelete <- keyArn:
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

// refreshAliasesTask will update the alias of all keys in the cache every 6 hours.
// Aliases will be updated to the same key they already have.
// The consequence of this is that the field LastUpdatedDate in each alias belonging to the server will be set to the current date.
// This is all with the goal of being able to detect keys that are not in use by any server.
func (p *Plugin) refreshAliasesTask(ctx context.Context) {
	ticker := p.hooks.clk.Ticker(refreshAliasesFrequency)
	defer ticker.Stop()

	p.notifyRefreshAliases(nil)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := p.refreshAliases(ctx)
			p.notifyRefreshAliases(err)
		}
	}
}

func (p *Plugin) refreshAliases(ctx context.Context) error {
	p.log.Debug("Refreshing aliases")
	p.mu.RLock()
	defer p.mu.RUnlock()
	var errs []string
	for _, entry := range p.entries {
		_, err := p.kmsClient.UpdateAlias(ctx, &kms.UpdateAliasInput{
			AliasName:   &entry.AliasName,
			TargetKeyId: &entry.Arn,
		})
		if err != nil {
			p.log.Error("Failed to refresh alias", aliasNameTag, entry.AliasName, keyArnTag, entry.Arn, reasonTag, err)
			errs = append(errs, err.Error())
		}
	}

	if errs != nil {
		return fmt.Errorf(strings.Join(errs, ": "))
	}
	return nil
}

// disposeAliasesTask will be run every 24hs.
// It will delete aliases that have a LastUpdatedDate value older than 48hs.
// It will also delete the keys asociated with them.
// It will only delete aliases belonging to the current trust domain but not the current server.
// disposeAliasesTask relies on how aliases are built with prefixes to do all this.
// Alias example: `alias/SPIRE_SERVER/{TRUST_DOMAIN}/{SERVER_ID}/{KEY_ID}`
func (p *Plugin) disposeAliasesTask(ctx context.Context) {
	ticker := p.hooks.clk.Ticker(disposeAliasesFrequency)
	defer ticker.Stop()

	p.notifyDisposeAliases(nil)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := p.disposeAliases(ctx)
			p.notifyDisposeAliases(err)
		}
	}
}

func (p *Plugin) disposeAliases(ctx context.Context) error {
	p.log.Debug("Looking for aliases in trust domain to dispose")
	paginator := kms.NewListAliasesPaginator(p.kmsClient, &kms.ListAliasesInput{Limit: aws.Int32(100)})
	var errs []string

	for {
		aliasesResp, err := paginator.NextPage(ctx)
		switch {
		case err != nil:
			p.log.Error("Failed to fetch aliases to dispose", reasonTag, err)
			return err
		case aliasesResp == nil:
			p.log.Error("Failed to fetch aliases to dispose: nil response")
			return err
		}

		for _, alias := range aliasesResp.Aliases {
			switch {
			case alias.AliasName == nil || alias.LastUpdatedDate == nil || alias.AliasArn == nil:
				continue
				// if alias does not belong to trust domain skip
			case !strings.HasPrefix(*alias.AliasName, p.aliasPrefixForTrustDomain()):
				continue
			// if alias belongs to current server skip
			case strings.HasPrefix(*alias.AliasName, p.aliasPrefixForServer()):
				continue
			}

			now := p.hooks.clk.Now()
			diff := now.Sub(*alias.LastUpdatedDate)
			if diff < aliasThreshold {
				continue
			}
			log := p.log.With(aliasNameTag, alias.AliasName)
			log.Debug("Found alias in trust domain beyond threshold")

			describeResp, err := p.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: alias.AliasArn})
			switch {
			case err != nil:
				log.Error("Failed to describe key to dispose", reasonTag, err)
				errs = append(errs, err.Error())
				continue
			case describeResp == nil || describeResp.KeyMetadata == nil || describeResp.KeyMetadata.Arn == nil:
				log.Error("Malformed describe key response while trying to dispose")
				continue
			case !describeResp.KeyMetadata.Enabled:
				continue
			}
			log = log.With(keyArnTag, *describeResp.KeyMetadata.Arn)

			_, err = p.kmsClient.DeleteAlias(ctx, &kms.DeleteAliasInput{AliasName: alias.AliasName})
			if err != nil {
				p.log.Error("Failed to delete alias to dispose", reasonTag, err)
				errs = append(errs, err.Error())
				continue
			}

			select {
			case p.scheduleDelete <- *describeResp.KeyMetadata.Arn:
				log.Debug("Key enqueued for deletion")
			default:
				log.Error("Failed to enqueue key for deletion")
			}
		}

		if !paginator.HasMorePages() {
			break
		}
	}

	if errs != nil {
		return fmt.Errorf(strings.Join(errs, ": "))
	}

	return nil
}

// disposeKeysTask will be run every 48hs.
// It will delete keys that have a CreationDate value older than 48hs.
// It will only delete keys belonging to the current trust domain and without an alias.
// disposeKeysTask relies on how the keys description is built to do all this.
// Key description example: `SPIRE_SERVER/{TRUST_DOMAIN}`
// Keys belonging to a server should never be without an alias.
// The goal of this task is to remove keys that ended in this invalid state during a failure on alias assignment.
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

func (p *Plugin) disposeKeys(ctx context.Context) error {
	p.log.Debug("Looking for keys in trust domain to dispose")
	paginator := kms.NewListKeysPaginator(p.kmsClient, &kms.ListKeysInput{Limit: aws.Int32(1000)})
	var errs []string

	for {
		keysResp, err := paginator.NextPage(ctx)
		switch {
		case err != nil:
			p.log.Error("Failed to fetch keys to dispose", reasonTag, err)
			return err
		case keysResp == nil:
			p.log.Error("Failed to fetch keys to dispose: nil response")
			return err
		}

		for _, key := range keysResp.Keys {
			if key.KeyArn == nil {
				continue
			}

			log := p.log.With(keyArnTag, key.KeyArn)

			describeResp, err := p.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: key.KeyArn})
			switch {
			case err != nil:
				log.Error("Failed to describe key to dispose", reasonTag, err)
				errs = append(errs, err.Error())
				continue
			case describeResp == nil ||
				describeResp.KeyMetadata == nil ||
				describeResp.KeyMetadata.Description == nil ||
				describeResp.KeyMetadata.CreationDate == nil:
				log.Error("Malformed describe key response while trying to dispose")
				continue
			case !describeResp.KeyMetadata.Enabled:
				continue
			}

			// if key does not belong to trust domain skip
			if *describeResp.KeyMetadata.Description != p.descriptionPrefixForTrustDomain() {
				continue
			}

			// if key has alias skip
			aliasesResp, err := p.kmsClient.ListAliases(ctx, &kms.ListAliasesInput{KeyId: key.KeyArn, Limit: aws.Int32(1)})
			switch {
			case err != nil:
				log.Error("Failed to fetch alias for key", reasonTag, err)
				errs = append(errs, err.Error())
				continue
			case aliasesResp == nil || len(aliasesResp.Aliases) > 0:
				continue
			}

			now := p.hooks.clk.Now()
			diff := now.Sub(*describeResp.KeyMetadata.CreationDate)
			if diff < keyThreshold {
				continue
			}

			log.Debug("Found key in trust domain beyond threshold")

			select {
			case p.scheduleDelete <- *describeResp.KeyMetadata.Arn:
				log.Debug("Key enqueued for deletion")
			default:
				log.Error("Failed to enqueue key for deletion")
			}
		}

		if !paginator.HasMorePages() {
			break
		}
	}
	if errs != nil {
		return fmt.Errorf(strings.Join(errs, ": "))
	}

	return nil
}

func (p *Plugin) aliasFromSpireKeyID(spireKeyID string) string {
	return path.Join(p.aliasPrefixForServer(), spireKeyID)
}

func (p *Plugin) descriptionFromSpireKeyID(spireKeyID string) string {
	return path.Join(p.descriptionPrefixForTrustDomain(), spireKeyID)
}

func (p *Plugin) descriptionPrefixForTrustDomain() string {
	trustDomain := sanitizeTrustDomain(p.trustDomain)
	return path.Join("SPIRE_SERVER_KEY/", trustDomain)
}

func (p *Plugin) aliasPrefixForServer() string {
	return path.Join(p.aliasPrefixForTrustDomain(), p.serverID)
}

func (p *Plugin) aliasPrefixForTrustDomain() string {
	trustDomain := sanitizeTrustDomain(p.trustDomain)
	return path.Join(aliasPrefix, trustDomain)
}

func (p *Plugin) notifyDelete(err error) {
	if p.hooks.scheduleDeleteSignal != nil {
		p.hooks.scheduleDeleteSignal <- err
	}
}

func (p *Plugin) notifyRefreshAliases(err error) {
	if p.hooks.refreshAliasesSignal != nil {
		p.hooks.refreshAliasesSignal <- err
	}
}

func (p *Plugin) notifyDisposeAliases(err error) {
	if p.hooks.disposeAliasesSignal != nil {
		p.hooks.disposeAliasesSignal <- err
	}
}

func (p *Plugin) notifyDisposeKeys(err error) {
	if p.hooks.disposeKeysSignal != nil {
		p.hooks.disposeKeysSignal <- err
	}
}

func sanitizeTrustDomain(trustDomain string) string {
	return strings.Replace(trustDomain, ".", "_", -1)
}

// parseAndValidateConfig returns an error if any configuration provided does not meet acceptable criteria
func parseAndValidateConfig(c string) (*Config, error) {
	config := new(Config)

	if err := hcl.Decode(config, c); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if config.Region == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is missing a region")
	}

	if config.ServerIDFilePath == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is missing server id file path")
	}

	return config, nil
}

func signingAlgorithmForKMS(keyType keymanagerv0.KeyType, signerOpts interface{}) (types.SigningAlgorithmSpec, error) {
	var (
		hashAlgo keymanagerv0.HashAlgorithm
		isPSS    bool
	)

	switch opts := signerOpts.(type) {
	case *keymanagerv0.SignDataRequest_HashAlgorithm:
		hashAlgo = opts.HashAlgorithm
		isPSS = false
	case *keymanagerv0.SignDataRequest_PssOptions:
		if opts.PssOptions == nil {
			return "", errors.New("PSS options are required")
		}
		hashAlgo = opts.PssOptions.HashAlgorithm
		isPSS = true
		// opts.PssOptions.SaltLength is handled by KMS. The salt length matches the bits of the hashing algorithm.
	default:
		return "", fmt.Errorf("unsupported signer opts type %T", opts)
	}

	isRSA := keyType == keymanagerv0.KeyType_RSA_2048 || keyType == keymanagerv0.KeyType_RSA_4096

	switch {
	case hashAlgo == keymanagerv0.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM:
		return "", errors.New("hash algorithm is required")
	case keyType == keymanagerv0.KeyType_EC_P256 && hashAlgo == keymanagerv0.HashAlgorithm_SHA256:
		return types.SigningAlgorithmSpecEcdsaSha256, nil
	case keyType == keymanagerv0.KeyType_EC_P384 && hashAlgo == keymanagerv0.HashAlgorithm_SHA384:
		return types.SigningAlgorithmSpecEcdsaSha384, nil
	case isRSA && !isPSS && hashAlgo == keymanagerv0.HashAlgorithm_SHA256:
		return types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
	case isRSA && !isPSS && hashAlgo == keymanagerv0.HashAlgorithm_SHA384:
		return types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
	case isRSA && !isPSS && hashAlgo == keymanagerv0.HashAlgorithm_SHA512:
		return types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
	case isRSA && isPSS && hashAlgo == keymanagerv0.HashAlgorithm_SHA256:
		return types.SigningAlgorithmSpecRsassaPssSha256, nil
	case isRSA && isPSS && hashAlgo == keymanagerv0.HashAlgorithm_SHA384:
		return types.SigningAlgorithmSpecRsassaPssSha384, nil
	case isRSA && isPSS && hashAlgo == keymanagerv0.HashAlgorithm_SHA512:
		return types.SigningAlgorithmSpecRsassaPssSha512, nil
	default:
		return "", fmt.Errorf("unsupported combination of keytype: %v and hashing algorithm: %v", keyType, hashAlgo)
	}
}

func keyTypeFromKeySpec(keySpec types.CustomerMasterKeySpec) (keymanagerv0.KeyType, bool) {
	switch keySpec {
	case types.CustomerMasterKeySpecRsa2048:
		return keymanagerv0.KeyType_RSA_2048, true
	case types.CustomerMasterKeySpecRsa4096:
		return keymanagerv0.KeyType_RSA_4096, true
	case types.CustomerMasterKeySpecEccNistP256:
		return keymanagerv0.KeyType_EC_P256, true
	case types.CustomerMasterKeySpecEccNistP384:
		return keymanagerv0.KeyType_EC_P384, true
	default:
		return keymanagerv0.KeyType_UNSPECIFIED_KEY_TYPE, false
	}
}

func keySpecFromKeyType(keyType keymanagerv0.KeyType) (types.CustomerMasterKeySpec, bool) {
	switch keyType {
	case keymanagerv0.KeyType_RSA_2048:
		return types.CustomerMasterKeySpecRsa2048, true
	case keymanagerv0.KeyType_RSA_4096:
		return types.CustomerMasterKeySpecRsa4096, true
	case keymanagerv0.KeyType_EC_P256:
		return types.CustomerMasterKeySpecEccNistP256, true
	case keymanagerv0.KeyType_EC_P384:
		return types.CustomerMasterKeySpecEccNistP384, true
	default:
		return "", false
	}
}

func min(x, y time.Duration) time.Duration {
	if x < y {
		return x
	}
	return y
}

func loadServerID(idPath string) (string, error) {
	// get id from path
	data, err := ioutil.ReadFile(idPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return createServerID(idPath)
	case err != nil:
		return "", status.Errorf(codes.Internal, "failed to read server id from path: %v", err)
	}

	// validate what we got is a uuid
	serverID, err := uuid.FromString(string(data))
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to parse server id from path: %v", err)
	}
	return serverID.String(), nil
}

func createServerID(idPath string) (string, error) {
	// generate id
	u, err := uuid.NewV4()
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to generate id for server: %v", err)
	}
	id := u.String()

	// persist id
	err = ioutil.WriteFile(idPath, []byte(id), 0600)
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to persist server id on path: %v", err)
	}
	return id, nil
}
