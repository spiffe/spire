package awskms

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	rgtatypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/gofrs/uuid/v5"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName  = "aws_kms"
	aliasPrefix = "alias/SPIRE_SERVER/"

	// Logging tags
	keyArnTag    = "key_arn"
	aliasNameTag = "alias_name"
	reasonTag    = "reason"

	// KMS resource tags for key discovery
	tagKeyServerTD   = "spire-server-td"   // Trust domain (no hashing needed - AWS allows dots and long values)
	tagKeyServerID   = "spire-server-id"   // Server identifier
	tagKeyLastUpdate = "spire-last-update" // Unix timestamp of last update
	tagKeyActive     = "spire-active"      // "true" if key is actively managed
	tagKeySPIREKeyID = "spire-key-id"      // SPIRE key identifier

	// Alias-based discovery task frequencies (legacy; will be deprecated in a future version and removed in a later one)
	refreshAliasesFrequency = time.Hour * 6
	disposeAliasesFrequency = time.Hour * 24
	aliasThreshold          = time.Hour * 24 * 14 // two weeks
	disposeKeysFrequency    = time.Hour * 48
	keyThreshold            = time.Hour * 48 // 48 hours for orphaned keys without aliases

	// Tag-based discovery task frequencies
	keepActiveKeysFrequency     = time.Hour * 6
	disposeKeysViaTagsFrequency = time.Hour * 48
	keyThresholdForTagDiscovery = time.Hour * 24 * 14 // two weeks for tagged keys
)

var (
	validTagKeyPattern   = regexp.MustCompile(`^[\p{L}\p{N}\s+\-=._:/@]+$`)
	validTagValuePattern = regexp.MustCompile(`^[\p{L}\p{N}\s+\-=._:/@]*$`)
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
	newKMSClient     func(aws.Config) (kmsClient, error)
	newTaggingClient func(aws.Config) (taggingClient, error)
	newSTSClient     func(aws.Config) (stsClient, error)
	clk              clock.Clock
	// just for testing
	scheduleDeleteSignal chan error
	refreshAliasesSignal chan error
	disposeAliasesSignal chan error
	disposeKeysSignal    chan error
	keepActiveKeysSignal chan error
}

// Plugin is the main representation of this keymanager plugin
type Plugin struct {
	keymanagerv1.UnsafeKeyManagerServer
	configv1.UnsafeConfigServer

	log            hclog.Logger
	mu             sync.RWMutex
	entries        map[string]keyEntry
	kmsClient      kmsClient
	taggingClient  taggingClient
	stsClient      stsClient
	trustDomain    string
	serverID       string
	scheduleDelete chan string
	cancelTasks    context.CancelFunc
	hooks          pluginHooks
	keyPolicy      *string
	keyTags        []types.Tag

	// useTagBasedDiscovery indicates whether to use tag-based or alias-based key discovery
	useTagBasedDiscovery bool
}

// Config provides configuration context for the plugin
type Config struct {
	AccessKeyID        string            `hcl:"access_key_id" json:"access_key_id"`
	SecretAccessKey    string            `hcl:"secret_access_key" json:"secret_access_key"`
	Region             string            `hcl:"region" json:"region"`
	KeyIdentifierFile  string            `hcl:"key_identifier_file" json:"key_identifier_file"`
	KeyIdentifierValue string            `hcl:"key_identifier_value" json:"key_identifier_value"`
	KeyPolicyFile      string            `hcl:"key_policy_file" json:"key_policy_file"`
	KeyTags            map[string]string `hcl:"key_tags" json:"key_tags"`

	// EnableTagBasedKeyDiscovery enables the use of AWS Resource Groups Tagging API
	// for efficient key discovery instead of the legacy alias-based approach.
	// When enabled, keys are discovered using SPIRE-specific tags (spire-server-td,
	// spire-server-id, spire-active).
	// This eliminates the need for broad ListKeys + DescribeKey permissions and reduces API costs.
	//
	// Default: false (uses legacy alias-based discovery)
	// In a future SPIRE version, this will default to true. The alias-based
	// approach will be deprecated in a future version and removed in a later one.
	//
	// Note: When enabled, the plugin requires the tag:GetResources IAM
	// permission (from the AWS Resource Groups Tagging API).
	EnableTagBasedKeyDiscovery bool `hcl:"enable_tag_based_key_discovery" json:"enable_tag_based_key_discovery"`
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *Config {
	newConfig := new(Config)
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	if newConfig.Region == "" {
		status.ReportError("configuration is missing a region")
	}

	if newConfig.KeyIdentifierValue != "" {
		re := regexp.MustCompile(".*[^A-z0-9/_-].*")
		if re.MatchString(newConfig.KeyIdentifierValue) {
			status.ReportError("Key identifier must contain only alphanumeric characters, forward slashes (/), underscores (_), and dashes (-)")
		}
		if strings.HasPrefix(newConfig.KeyIdentifierValue, "alias/aws/") {
			status.ReportError("Key identifier must not start with alias/aws/")
		}
		if len(newConfig.KeyIdentifierValue) > 256 {
			status.ReportError("Key identifier must not be longer than 256 characters")
		}
	}

	if newConfig.KeyIdentifierFile == "" && newConfig.KeyIdentifierValue == "" {
		status.ReportError("configuration requires a key identifier file or a key identifier value")
	}

	if newConfig.KeyIdentifierFile != "" && newConfig.KeyIdentifierValue != "" {
		status.ReportError("configuration can't have a key identifier file and a key identifier value at the same time")
	}

	if len(newConfig.KeyTags) > 0 {
		if err := validateTags(newConfig.KeyTags); err != nil {
			status.ReportErrorf("invalid configuration for key tags: %v", err)
		}
	}

	return newConfig
}

// New returns an instantiated plugin
func New() *Plugin {
	return newPlugin(newKMSClient, newTaggingClient, newSTSClient)
}

func newPlugin(
	newKMSClient func(aws.Config) (kmsClient, error),
	newTaggingClient func(aws.Config) (taggingClient, error),
	newSTSClient func(aws.Config) (stsClient, error),
) *Plugin {
	return &Plugin{
		entries: make(map[string]keyEntry),
		hooks: pluginHooks{
			newKMSClient:     newKMSClient,
			newTaggingClient: newTaggingClient,
			newSTSClient:     newSTSClient,
			clk:              clock.New(),
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
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	if newConfig.KeyPolicyFile != "" {
		policyBytes, err := os.ReadFile(newConfig.KeyPolicyFile)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to read file configured in 'key_policy_file': %v", err)
		}
		policyStr := string(policyBytes)
		p.keyPolicy = &policyStr
	}

	serverID := newConfig.KeyIdentifierValue
	if serverID == "" {
		serverID, err = getOrCreateServerID(newConfig.KeyIdentifierFile)
		if err != nil {
			return nil, err
		}
	}
	p.log.Debug("Loaded server id", "server_id", serverID)

	awsCfg, err := newAWSConfig(ctx, newConfig)
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

	// Determine which discovery mode to use
	useTagBasedDiscovery := newConfig.EnableTagBasedKeyDiscovery

	if useTagBasedDiscovery {
		p.log.Info("Tag-based key discovery enabled")
	} else {
		p.log.Warn("Alias-based key discovery will be deprecated in a future version and removed in a later one. " +
			"Enable 'enable_tag_based_key_discovery' to switch to tag-based discovery, which efficiently " +
			"finds only the keys managed by this plugin instance.")
	}

	// Initialize the appropriate fetcher based on configuration
	var keyEntries []*keyEntry
	var spireTags []types.Tag
	if useTagBasedDiscovery {
		// Build SPIRE-specific tags so they can be used during migration
		// and applied to newly created keys.
		spireTags = p.buildSPIRETags(serverID, req.CoreConfiguration.TrustDomain)
		// Create tagging client for tag-based discovery
		tc, err := p.hooks.newTaggingClient(awsCfg)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create tagging client: %v", err)
		}

		fetcher := &keyFetcher{
			log:           p.log,
			kmsClient:     kc,
			taggingClient: tc,
			serverID:      serverID,
			trustDomain:   req.CoreConfiguration.TrustDomain,
		}
		p.log.Debug("Fetching keys using tag-based discovery from AWS Resource Groups Tagging API")
		lastUpdate := strconv.FormatInt(p.hooks.clk.Now().Unix(), 10)
		keyEntries, err = fetcher.fetchKeyEntriesWithMigration(ctx, spireTags, lastUpdate)
		if err != nil {
			return nil, err
		}
		p.taggingClient = tc
	} else {
		// Use legacy alias-based discovery
		fetcher := &keyFetcher{
			log:         p.log,
			kmsClient:   kc,
			serverID:    serverID,
			trustDomain: req.CoreConfiguration.TrustDomain,
		}
		p.log.Debug("Fetching keys using legacy alias-based discovery from KMS")
		keyEntries, err = fetcher.fetchKeyEntriesViaAlias(ctx)
		if err != nil {
			return nil, err
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.setCache(keyEntries)
	p.kmsClient = kc
	p.stsClient = sc
	p.trustDomain = req.CoreConfiguration.TrustDomain
	p.serverID = serverID
	p.useTagBasedDiscovery = useTagBasedDiscovery

	// Build the tag list applied to every new key. SPIRE-specific tags are
	// only included when tag-based discovery is enabled, so that the legacy
	// alias-based path does not require the kms:TagResource permission.
	switch {
	case useTagBasedDiscovery && len(newConfig.KeyTags) > 0:
		userTags := buildKeyTags(newConfig.KeyTags)
		// Build a fresh slice to avoid mutating the spireTags backing array.
		p.keyTags = make([]types.Tag, 0, len(spireTags)+len(userTags))
		p.keyTags = append(p.keyTags, spireTags...)
		p.keyTags = append(p.keyTags, userTags...)
	case useTagBasedDiscovery:
		p.keyTags = spireTags
	case len(newConfig.KeyTags) > 0:
		p.keyTags = buildKeyTags(newConfig.KeyTags)
	default:
		p.keyTags = nil
	}

	// cancels previous tasks in case of re-configure
	if p.cancelTasks != nil {
		p.cancelTasks()
	}

	// Start background tasks based on discovery mode
	ctx, p.cancelTasks = context.WithCancel(context.Background())
	go p.scheduleDeleteTask(ctx)

	// Always refresh aliases so a downgrade to a version without
	// tag-based discovery still finds keys with fresh aliases.
	go p.refreshAliasesTask(ctx)

	if useTagBasedDiscovery {
		go p.keepActiveKeysTask(ctx)
		go p.disposeKeysViaTagsTask(ctx)
	} else {
		go p.disposeAliasesTask(ctx)
		go p.disposeKeysTask(ctx)
	}

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(ctx context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
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
		Description: aws.String(description),
		KeyUsage:    types.KeyUsageTypeSignVerify,
		KeySpec:     keySpec,
		Policy:      p.keyPolicy,
	}

	if p.useTagBasedDiscovery {
		// When tag-based discovery is enabled, append the per-key SPIRE key
		// ID tag so the key can be looked up by ID via the tagging API, and
		// stamp spire-last-update so the key is immediately eligible for
		// staleness evaluation. Stamping at creation (rather than waiting for
		// the first keepActiveKeys tick) ensures a key is never left with
		// spire-active=true but no spire-last-update, which would make it
		// undisposable by other servers if this server dies before that tick.
		// Build a fresh slice to avoid mutating the shared p.keyTags slice.
		tags := make([]types.Tag, len(p.keyTags), len(p.keyTags)+2)
		copy(tags, p.keyTags)
		tags = append(tags,
			types.Tag{
				TagKey:   aws.String(tagKeySPIREKeyID),
				TagValue: aws.String(spireKeyID),
			},
			types.Tag{
				TagKey:   aws.String(tagKeyLastUpdate),
				TagValue: aws.String(strconv.FormatInt(p.hooks.clk.Now().Unix(), 10)),
			},
		)
		createKeyInput.Tags = tags
	} else if len(p.keyTags) > 0 {
		// Legacy alias-based mode: only apply user-defined tags (if any).
		createKeyInput.Tags = p.keyTags
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

// scheduleDeleteTask ia a long-running task that deletes keys that were rotated
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
		// Resolve the alias's current target to avoid reverting a rotation
		// performed by another replica sharing the same key_identifier_value.
		describeResp, err := p.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{
			KeyId: aws.String(entry.AliasName),
		})
		if err != nil {
			p.log.Error("Failed to describe key for alias refresh", aliasNameTag, entry.AliasName, reasonTag, err)
			errs = append(errs, err.Error())
			continue
		}
		if describeResp == nil || describeResp.KeyMetadata == nil || describeResp.KeyMetadata.Arn == nil {
			p.log.Error("Malformed describe key response during alias refresh", aliasNameTag, entry.AliasName)
			errs = append(errs, fmt.Sprintf("malformed describe key response for alias %q", entry.AliasName))
			continue
		}

		currentArn := *describeResp.KeyMetadata.Arn
		if currentArn != entry.Arn {
			p.log.Warn("Alias target differs from cache, skipping refresh to avoid reverting a rotation",
				aliasNameTag, entry.AliasName, "cached_arn", entry.Arn, "current_arn", currentArn)
			continue
		}

		_, err = p.kmsClient.UpdateAlias(ctx, &kms.UpdateAliasInput{
			AliasName:   &entry.AliasName,
			TargetKeyId: &entry.Arn,
		})
		if err != nil {
			p.log.Error("Failed to refresh alias", aliasNameTag, entry.AliasName, keyArnTag, entry.Arn, reasonTag, err)
			errs = append(errs, err.Error())
		}
	}

	if errs != nil {
		return errors.New(strings.Join(errs, ": "))
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
		return errors.New(strings.Join(errs, ": "))
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
			if !strings.HasPrefix(*describeResp.KeyMetadata.Description, p.descriptionPrefixForTrustDomain()) {
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
		return errors.New(strings.Join(errs, ": "))
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
		p.log.Warn("In a future version of SPIRE, it will be mandatory for the SPIRE servers to assume an AWS IAM Role when using the default AWS KMS key policy. Please assign an IAM role to this SPIRE Server instance.", reasonTag, err)
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

func keyTypeFromKeySpec(keySpec types.KeySpec) (keymanagerv1.KeyType, bool) {
	switch keySpec {
	case types.KeySpecRsa2048:
		return keymanagerv1.KeyType_RSA_2048, true
	case types.KeySpecRsa4096:
		return keymanagerv1.KeyType_RSA_4096, true
	case types.KeySpecEccNistP256:
		return keymanagerv1.KeyType_EC_P256, true
	case types.KeySpecEccNistP384:
		return keymanagerv1.KeyType_EC_P384, true
	default:
		return keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE, false
	}
}

func keySpecFromKeyType(keyType keymanagerv1.KeyType) (types.KeySpec, bool) {
	switch keyType {
	case keymanagerv1.KeyType_RSA_2048:
		return types.KeySpecRsa2048, true
	case keymanagerv1.KeyType_RSA_4096:
		return types.KeySpecRsa4096, true
	case keymanagerv1.KeyType_EC_P256:
		return types.KeySpecEccNistP256, true
	case keymanagerv1.KeyType_EC_P384:
		return types.KeySpecEccNistP384, true
	default:
		return "", false
	}
}

func getOrCreateServerID(idPath string) (string, error) {
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

func validateTags(tags map[string]string) error {
	const maxTags = 50
	if len(tags) > maxTags {
		return fmt.Errorf("too many tags: %d tags exceed AWS limit of 50", len(tags))
	}

	for key, value := range tags {
		if key == "" {
			return errors.New("tag key cannot be empty")
		}
		if len(key) > 128 {
			return fmt.Errorf("tag key %q exceeds maximum length of 128 characters", key)
		}
		if strings.HasPrefix(strings.ToLower(key), "aws:") {
			return fmt.Errorf("tag key %q uses reserved prefix 'aws:'", key)
		}
		if strings.HasPrefix(strings.ToLower(key), "spire-") {
			return fmt.Errorf("tag key %q uses reserved prefix 'spire-'", key)
		}
		if !validTagKeyPattern.MatchString(key) {
			return fmt.Errorf("tag key %q contains invalid characters (allowed: letters, numbers, spaces, + - = . _ : / @)", key)
		}

		if len(value) > 256 {
			return fmt.Errorf("tag value for key %q exceeds maximum length of 256 characters", key)
		}
		if !validTagValuePattern.MatchString(value) {
			return fmt.Errorf("tag value for key %q contains invalid characters (allowed: letters, numbers, spaces, + - = . _ : / @)", key)
		}
	}

	return nil
}

func buildKeyTags(tags map[string]string) []types.Tag {
	keyTags := make([]types.Tag, 0, len(tags))

	for key, value := range tags {
		keyTags = append(keyTags, types.Tag{
			TagKey:   aws.String(key),
			TagValue: aws.String(value),
		})
	}

	return keyTags
}

// buildSPIRETags creates the SPIRE-specific tags that are added to all KMS keys
// at creation time. These tags enable efficient key discovery via the AWS
// Resource Groups Tagging API.
//
// Note: spire-last-update is intentionally omitted here. It is stamped
// separately at key creation and during migration (with the current
// timestamp) and refreshed on a regular schedule by keepActiveKeys.
func (p *Plugin) buildSPIRETags(serverID, trustDomain string) []types.Tag {
	return []types.Tag{
		{
			TagKey:   aws.String(tagKeyServerTD),
			TagValue: aws.String(trustDomain),
		},
		{
			TagKey:   aws.String(tagKeyServerID),
			TagValue: aws.String(serverID),
		},
		{
			TagKey:   aws.String(tagKeyActive),
			TagValue: aws.String("true"),
		},
	}
}

// encodeKeyID maps "." and "+" characters to the asciihex value using "_" as
// escape character. Currently, KMS does not support those characters to be used
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

// keepActiveKeysTask updates the spire-last-update tag on all managed keys every 6 hours.
// This allows detection of keys that are no longer in use by any server.
// This task only runs when tag-based discovery is enabled.
func (p *Plugin) keepActiveKeysTask(ctx context.Context) {
	ticker := p.hooks.clk.Ticker(keepActiveKeysFrequency)
	defer ticker.Stop()

	p.notifyKeepActiveKeys(nil)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := p.keepActiveKeys(ctx)
			p.notifyKeepActiveKeys(err)
		}
	}
}

// keepActiveKeys updates the last-update tag on all keys managed by this server.
func (p *Plugin) keepActiveKeys(ctx context.Context) error {
	p.log.Debug("Updating last-update tag on managed keys")

	// Snapshot entries under the lock so we don't hold it across network calls.
	p.mu.RLock()
	entries := make([]keyEntry, 0, len(p.entries))
	for _, e := range p.entries {
		entries = append(entries, e)
	}
	p.mu.RUnlock()

	now := strconv.FormatInt(p.hooks.clk.Now().Unix(), 10)
	var errs []string

	for _, entry := range entries {
		_, err := p.kmsClient.TagResource(ctx, &kms.TagResourceInput{
			KeyId: &entry.Arn,
			Tags: []types.Tag{
				{
					TagKey:   aws.String(tagKeyLastUpdate),
					TagValue: aws.String(now),
				},
			},
		})
		if err != nil {
			p.log.Error("Failed to update last-update tag", keyArnTag, entry.Arn, reasonTag, err)
			errs = append(errs, err.Error())
		}
	}

	if errs != nil {
		return errors.New(strings.Join(errs, ": "))
	}
	return nil
}

// disposeKeysViaTagsTask finds and disposes of stale keys using tag-based filtering.
// This runs every 48 hours and looks for keys with spire-active=true but with
// a spire-last-update timestamp older than 2 weeks that don't belong to this server.
// This is the tag-based equivalent of disposeAliasesTask.
func (p *Plugin) disposeKeysViaTagsTask(ctx context.Context) {
	ticker := p.hooks.clk.Ticker(disposeKeysViaTagsFrequency)
	defer ticker.Stop()

	p.notifyDisposeKeys(nil)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := p.disposeKeysViaTags(ctx)
			p.notifyDisposeKeys(err)
		}
	}
}

// disposeKeysViaTags uses the AWS Resource Groups Tagging API to find stale keys.
func (p *Plugin) disposeKeysViaTags(ctx context.Context) error {
	p.log.Debug("Looking for stale keys to dispose using tag-based discovery")

	now := p.hooks.clk.Now()
	staleThreshold := now.Add(-keyThresholdForTagDiscovery).Unix()

	// Find all keys in this trust domain that are active
	tagFilters := []rgtatypes.TagFilter{
		{
			Key:    aws.String(tagKeyServerTD),
			Values: []string{p.trustDomain},
		},
		{
			Key:    aws.String(tagKeyActive),
			Values: []string{"true"},
		},
	}

	paginator := resourcegroupstaggingapi.NewGetResourcesPaginator(p.taggingClient, &resourcegroupstaggingapi.GetResourcesInput{
		ResourceTypeFilters: []string{"kms:key"},
		TagFilters:          tagFilters,
	})

	var errs []string
	for {
		resourcesResp, err := paginator.NextPage(ctx)
		switch {
		case err != nil:
			if permErr := tagGetResourcesPermissionError(err); permErr != nil {
				p.log.Error("Failed to fetch keys for disposal", reasonTag, permErr)
				return permErr
			}
			p.log.Error("Failed to fetch keys for disposal", reasonTag, err)
			return err
		case resourcesResp == nil:
			p.log.Error("Failed to fetch keys for disposal: nil response")
			return errors.New("nil response from tagging API")
		}

		for _, resource := range resourcesResp.ResourceTagMappingList {
			if resource.ResourceARN == nil {
				continue
			}

			keyArn := *resource.ResourceARN

			// Check if this key belongs to the current server
			var belongsToThisServer bool
			var lastUpdateTimestamp int64
			var hasLastUpdate bool
			var malformedTimestamp bool
			for _, tag := range resource.Tags {
				if tag.Key != nil && *tag.Key == tagKeyServerID && tag.Value != nil && *tag.Value == p.serverID {
					belongsToThisServer = true
				}
				if tag.Key != nil && *tag.Key == tagKeyLastUpdate && tag.Value != nil {
					ts, err := strconv.ParseInt(*tag.Value, 10, 64)
					if err != nil {
						malformedTimestamp = true
						continue
					}
					lastUpdateTimestamp = ts
					hasLastUpdate = true
				}
			}

			if malformedTimestamp && !hasLastUpdate {
				p.log.Warn("Malformed spire-last-update tag value, skipping key",
					keyArnTag, keyArn)
				continue
			}

			// Skip keys belonging to this server
			if belongsToThisServer {
				continue
			}

			// Skip keys that have been updated recently. A key with no
			// spire-last-update tag has lastUpdateTimestamp == 0 (the Unix
			// epoch), the oldest possible value, so it is treated as stale:
			// every key managed by the plugin is stamped at creation and
			// migration, and a missing value indicates an abandoned key.
			if lastUpdateTimestamp > staleThreshold {
				continue
			}

			log := p.log.With(keyArnTag, keyArn)
			log.Debug("Found stale key beyond threshold")

			// Schedule the key for deletion synchronously and only mark it
			// inactive once the deletion has been scheduled. Marking
			// spire-active=false drops the key from the GetResources(active=true)
			// filter, so doing it before the deletion is actually scheduled
			// could orphan the key if the server stops in between, and tag mode
			// has no creation-date orphan sweeper to fall back on like the
			// legacy alias path does.
			_, err := p.kmsClient.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
				KeyId:               &keyArn,
				PendingWindowInDays: aws.Int32(7),
			})
			// A key that is already pending deletion (for example, scheduled on
			// a previous cycle that stopped before marking it inactive) is
			// treated as success so the spire-active tag can still be cleared.
			// Any other error leaves the key active so it is retried next cycle.
			var invalidState *types.KMSInvalidStateException
			if err != nil && !errors.As(err, &invalidState) {
				log.Error("Failed to schedule key for deletion", reasonTag, err)
				errs = append(errs, err.Error())
				continue
			}
			log.Debug("Key scheduled for deletion")

			// Mark the key as inactive by updating the spire-active tag.
			_, err = p.kmsClient.TagResource(ctx, &kms.TagResourceInput{
				KeyId: &keyArn,
				Tags: []types.Tag{
					{
						TagKey:   aws.String(tagKeyActive),
						TagValue: aws.String("false"),
					},
				},
			})
			if err != nil {
				log.Error("Failed to mark key as inactive", reasonTag, err)
				errs = append(errs, err.Error())
			}
		}

		if !paginator.HasMorePages() {
			break
		}
	}

	if errs != nil {
		return errors.New(strings.Join(errs, ": "))
	}
	return nil
}

func (p *Plugin) notifyKeepActiveKeys(err error) {
	if p.hooks.keepActiveKeysSignal != nil {
		p.hooks.keepActiveKeysSignal <- err
	}
}
