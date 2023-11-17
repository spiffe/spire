package awskms

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/gofrs/uuid/v5"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/diskutil"
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
	aliasThreshold          = time.Hour * 24 * 14 // two weeks

	disposeKeysFrequency = time.Hour * 48
	keyThreshold         = time.Hour * 48
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
	Arn       string
	AliasName string
	PublicKey *keymanagerv1.PublicKey
}

type pluginHooks struct {
	newKMSClient func(aws.Config) (kmsClient, error)
	newSTSClient func(aws.Config) (stsClient, error)
	clk          clock.Clock
	// just for testing
	scheduleDeleteSignal chan error
	refreshAliasesSignal chan error
	disposeAliasesSignal chan error
	disposeKeysSignal    chan error
}

// Plugin is the main representation of this keymanager plugin
type Plugin struct {
	keymanagerv1.UnsafeKeyManagerServer
	configv1.UnsafeConfigServer

	log            hclog.Logger
	mu             sync.RWMutex
	entries        map[string]keyEntry
	kmsClient      kmsClient
	stsClient      stsClient
	trustDomain    string
	serverID       string
	scheduleDelete chan string
	cancelTasks    context.CancelFunc
	hooks          pluginHooks
	keyPolicy      *string
}

// Config provides configuration context for the plugin
type Config struct {
	AccessKeyID     string `hcl:"access_key_id" json:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key" json:"secret_access_key"`
	Region          string `hcl:"region" json:"region"`
	KeyMetadataFile string `hcl:"key_metadata_file" json:"key_metadata_file"`
	KeyPolicyFile   string `hcl:"key_policy_file" json:"key_policy_file"`
}

// New returns an instantiated plugin
func New() *Plugin {
	return newPlugin(newKMSClient, newSTSClient)
}

func newPlugin(
	newKMSClient func(aws.Config) (kmsClient, error),
	newSTSClient func(aws.Config) (stsClient, error),
) *Plugin {
	return &Plugin{
		entries: make(map[string]keyEntry),
		hooks: pluginHooks{
			newKMSClient: newKMSClient,
			newSTSClient: newSTSClient,
			clk:          clock.New(),
		},
		scheduleDelete: make(chan string, 120),
	}
}

// SetLogger sets a logger
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Configure sets up the plugin
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config, err := parseAndValidateConfig(req.HclConfiguration)
	if err != nil {
		return nil, err
	}

	serverID, err := loadServerID(config.KeyMetadataFile)
	if err != nil {
		return nil, err
	}
	p.log.Debug("Loaded server id", "server_id", serverID)

	if config.KeyPolicyFile != "" {
		policyBytes, err := os.ReadFile(config.KeyPolicyFile)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to read file configured in 'key_policy_file': %v", err)
		}
		policyStr := string(policyBytes)
		p.keyPolicy = &policyStr
	}

	awsCfg, err := newAWSConfig(ctx, config)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create client configuration: %v", err)
	}

	sc, err := p.hooks.newSTSClient(awsCfg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create STS client: %v", err)
	}

	kc, err := p.hooks.newKMSClient(awsCfg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create KMS client: %v", err)
	}

	fetcher := &keyFetcher{
		log:         p.log,
		kmsClient:   kc,
		serverID:    serverID,
		trustDomain: req.CoreConfiguration.TrustDomain,
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
	p.stsClient = sc
	p.trustDomain = req.CoreConfiguration.TrustDomain
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

	return &configv1.ConfigureResponse{}, nil
}

// GenerateKey creates a key in KMS. If a key already exists in the local storage, it is updated.
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

	err = p.assignAlias(ctx, newKeyEntry)
	if err != nil {
		return nil, err
	}

	p.entries[spireKeyID] = *newKeyEntry

	return &keymanagerv1.GenerateKeyResponse{
		PublicKey: newKeyEntry.PublicKey,
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

	keyEntry, hasKey := p.entries[req.KeyId]
	if !hasKey {
		return nil, status.Errorf(codes.NotFound, "key %q not found", req.KeyId)
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

	return &keymanagerv1.SignDataResponse{
		Signature:      signResp.Signature,
		KeyFingerprint: keyEntry.PublicKey.Fingerprint,
	}, nil
}

// GetPublicKey returns the public key for a given key
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

// GetPublicKeys return the publicKey for all the keys
func (p *Plugin) GetPublicKeys(context.Context, *keymanagerv1.GetPublicKeysRequest) (*keymanagerv1.GetPublicKeysResponse, error) {
	var keys []*keymanagerv1.PublicKey
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, key := range p.entries {
		keys = append(keys, key.PublicKey)
	}

	return &keymanagerv1.GetPublicKeysResponse{PublicKeys: keys}, nil
}

func (p *Plugin) createKey(ctx context.Context, spireKeyID string, keyType keymanagerv1.KeyType) (*keyEntry, error) {
	description := p.descriptionFromSpireKeyID(spireKeyID)
	keySpec, ok := keySpecFromKeyType(keyType)
	if !ok {
		return nil, status.Errorf(codes.Internal, "unsupported key type: %v", keyType)
	}

	if p.keyPolicy == nil {
		defaultPolicy, err := p.createDefaultPolicy(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to create policy: %v", err)
		}
		p.keyPolicy = defaultPolicy
	}

	createKeyInput := &kms.CreateKeyInput{
		Description:           aws.String(description),
		KeyUsage:              types.KeyUsageTypeSignVerify,
		CustomerMasterKeySpec: keySpec,
		Policy:                p.keyPolicy,
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
	if pub == nil || pub.KeyId == nil || len(pub.PublicKey) == 0 {
		return nil, status.Error(codes.Internal, "malformed get public key response")
	}

	return &keyEntry{
		Arn:       *key.KeyMetadata.Arn,
		AliasName: p.aliasFromSpireKeyID(spireKeyID),
		PublicKey: &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    pub.PublicKey,
			Fingerprint: makeFingerprint(pub.PublicKey),
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
				log.Error("Failed to schedule key deletion", reasonTag, "No such key")
				p.notifyDelete(err)
				continue
			}

			var invalidArnErr *types.InvalidArnException
			if errors.As(err, &invalidArnErr) {
				log.Error("Failed to schedule key deletion", reasonTag, "Invalid ARN")
				p.notifyDelete(err)
				continue
			}

			var invalidState *types.KMSInvalidStateException
			if errors.As(err, &invalidState) {
				log.Error("Failed to schedule key deletion", reasonTag, "Key was on invalid state for deletion")
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
		entry := entry
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
// It will delete aliases that have a LastUpdatedDate value older than two weeks.
// It will also delete the keys associated with them.
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
				log.Error("Failed to clean up old KMS keys.", reasonTag, fmt.Errorf("AWS API DescribeKey failed: %w", err))
				errs = append(errs, err.Error())
				continue
			case describeResp == nil || describeResp.KeyMetadata == nil || describeResp.KeyMetadata.Arn == nil:
				log.Error("Failed to clean up old KMS keys", reasonTag, "Missing data in AWS API DescribeKey response")
				continue
			case !describeResp.KeyMetadata.Enabled:
				continue
			}
			log = log.With(keyArnTag, *describeResp.KeyMetadata.Arn)

			_, err = p.kmsClient.DeleteAlias(ctx, &kms.DeleteAliasInput{AliasName: alias.AliasName})
			if err != nil {
				log.Error("Failed to clean up old KMS keys.", reasonTag, fmt.Errorf("AWS API DeleteAlias failed: %w", err))
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

			// if key does not belong to trust domain, skip it
			if *describeResp.KeyMetadata.Description != p.descriptionPrefixForTrustDomain() {
				continue
			}

			// if key has alias, skip it
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
	return path.Join(p.aliasPrefixForServer(), encodeKeyID(spireKeyID))
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

func (p *Plugin) createDefaultPolicy(ctx context.Context) (*string, error) {
	result, err := p.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("cannot get caller identity: %w", err)
	}

	accountID := *result.Account
	roleName, err := roleNameFromARN(*result.Arn)
	if err != nil {
		// the server has not assumed any role, use default KMS policy and log a warn message
		p.log.Warn("In a future version of SPIRE, it will be mandatory for the SPIRE servers to assume an AWS IAM Role when using the default AWS KMS key policy. Please assign an IAM role to this SPIRE Server instance.")
		return nil, nil
	}

	policy := fmt.Sprintf(`
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Sid": "Allow full access to the SPIRE Server role",
			"Effect": "Allow",
			"Principal": {
				"AWS": "arn:aws:iam::%s:role/%s"
			},
			"Action": "kms:*",
			"Resource": "*"
		},
		{
			"Sid": "Allow KMS console to display the key and policy",
			"Effect": "Allow",
			"Principal": {
			    "AWS": "arn:aws:iam::%s:root"
			},
			"Action": [
				"kms:Describe*",
				"kms:List*",
				"kms:Get*"
			],
			"Resource": "*"
		}
	]
}`,
		accountID, roleName, accountID)

	return &policy, nil
}

// roleNameFromARN returns the role name included in an ARN. If no role name exist
// an error is returned.
// ARN example: "arn:aws:sts::123456789:assumed-role/the-role-name/i-0001f4f25acfd1234",
func roleNameFromARN(arn string) (string, error) {
	arnSegments := strings.Split(arn, ":")
	lastSegment := arnSegments[len(arnSegments)-1]

	resource := strings.Split(lastSegment, "/")
	if len(resource) < 2 {
		return "", fmt.Errorf("incomplete resource, expected 'resource-type/resource-id' but got %q", lastSegment)
	}

	resourceType := resource[0]
	if resourceType != "assumed-role" {
		return "", fmt.Errorf("arn does not contain an assumed role: %q", arn)
	}

	roleName := resource[1]

	return roleName, nil
}

func sanitizeTrustDomain(trustDomain string) string {
	return strings.ReplaceAll(trustDomain, ".", "_")
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

	if config.KeyMetadataFile == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is missing server id file path")
	}

	return config, nil
}

func signingAlgorithmForKMS(keyType keymanagerv1.KeyType, signerOpts any) (types.SigningAlgorithmSpec, error) {
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
			return "", errors.New("PSS options are required")
		}
		hashAlgo = opts.PssOptions.HashAlgorithm
		isPSS = true
		// opts.PssOptions.SaltLength is handled by KMS. The salt length matches the bits of the hashing algorithm.
	default:
		return "", fmt.Errorf("unsupported signer opts type %T", opts)
	}

	isRSA := keyType == keymanagerv1.KeyType_RSA_2048 || keyType == keymanagerv1.KeyType_RSA_4096

	switch {
	case hashAlgo == keymanagerv1.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM:
		return "", errors.New("hash algorithm is required")
	case keyType == keymanagerv1.KeyType_EC_P256 && hashAlgo == keymanagerv1.HashAlgorithm_SHA256:
		return types.SigningAlgorithmSpecEcdsaSha256, nil
	case keyType == keymanagerv1.KeyType_EC_P384 && hashAlgo == keymanagerv1.HashAlgorithm_SHA384:
		return types.SigningAlgorithmSpecEcdsaSha384, nil
	case isRSA && !isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA256:
		return types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
	case isRSA && !isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA384:
		return types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
	case isRSA && !isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA512:
		return types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
	case isRSA && isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA256:
		return types.SigningAlgorithmSpecRsassaPssSha256, nil
	case isRSA && isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA384:
		return types.SigningAlgorithmSpecRsassaPssSha384, nil
	case isRSA && isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA512:
		return types.SigningAlgorithmSpecRsassaPssSha512, nil
	default:
		return "", fmt.Errorf("unsupported combination of keytype: %v and hashing algorithm: %v", keyType, hashAlgo)
	}
}

func keyTypeFromKeySpec(keySpec types.CustomerMasterKeySpec) (keymanagerv1.KeyType, bool) {
	switch keySpec {
	case types.CustomerMasterKeySpecRsa2048:
		return keymanagerv1.KeyType_RSA_2048, true
	case types.CustomerMasterKeySpecRsa4096:
		return keymanagerv1.KeyType_RSA_4096, true
	case types.CustomerMasterKeySpecEccNistP256:
		return keymanagerv1.KeyType_EC_P256, true
	case types.CustomerMasterKeySpecEccNistP384:
		return keymanagerv1.KeyType_EC_P384, true
	default:
		return keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE, false
	}
}

func keySpecFromKeyType(keyType keymanagerv1.KeyType) (types.CustomerMasterKeySpec, bool) {
	switch keyType {
	case keymanagerv1.KeyType_RSA_2048:
		return types.CustomerMasterKeySpecRsa2048, true
	case keymanagerv1.KeyType_RSA_4096:
		return types.CustomerMasterKeySpecRsa4096, true
	case keymanagerv1.KeyType_EC_P256:
		return types.CustomerMasterKeySpecEccNistP256, true
	case keymanagerv1.KeyType_EC_P384:
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
	data, err := os.ReadFile(idPath)
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
	err = diskutil.WritePrivateFile(idPath, []byte(id))
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to persist server id on path: %v", err)
	}
	return id, nil
}

func makeFingerprint(pkixData []byte) string {
	s := sha256.Sum256(pkixData)
	return hex.EncodeToString(s[:])
}

// encodeKeyID maps "." and "+" characters to the asciihex value using "_" as
// escape character. Currently KMS does not support those characters to be used
// as alias name.
func encodeKeyID(keyID string) string {
	keyID = strings.ReplaceAll(keyID, ".", "_2e")
	keyID = strings.ReplaceAll(keyID, "+", "_2b")
	return keyID
}

// decodeKeyID decodes "." and "+" from the asciihex value using "_" as
// escape character.
func decodeKeyID(keyID string) string {
	keyID = strings.ReplaceAll(keyID, "_2e", ".")
	keyID = strings.ReplaceAll(keyID, "_2b", "+")
	return keyID
}
