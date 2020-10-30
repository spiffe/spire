package kms

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/golang/protobuf/proto"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/keymanager"
	"github.com/zeebo/errs"
)

// TODOS:
// - timeouts

var (
	kmsErr = errs.Class("kms")
)

const (
	aliasPrefix = "alias/"
	keyPrefix   = "SPIRE_SERVER_KEY/"

	keyIDTag = "KeyID"
)

type keyEntry struct {
	KMSKeyID  string
	Alias     string
	PublicKey *keymanager.PublicKey
}

type Plugin struct {
	log       hclog.Logger
	mu        sync.RWMutex
	entries   map[string]keyEntry
	kmsClient kmsClient
}

type Config struct {
	AccessKeyID     string `hcl:"access_key_id" json:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key" json:"secret_access_key"`
	Region          string `hcl:"region" json:"region"`
}

func New() *Plugin {
	return &Plugin{
		entries: make(map[string]keyEntry),
	}
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	config, err := validateConfig(req.Configuration)
	if err != nil {
		return nil, err
	}

	p.kmsClient, err = newKMSClient(config)
	if err != nil {
		return nil, kmsErr.New("failed to create KMS client: %v", err)
	}

	// TODO: pagination
	p.log.Info("Fetching keys from KMS")
	aliasesResp, err := p.kmsClient.ListAliasesWithContext(ctx, &kms.ListAliasesInput{})
	if err != nil {
		return nil, kmsErr.New("failed to fetch keys: %v", err)
	}

	for _, alias := range aliasesResp.Aliases {
		entry, err := p.buildKeyEntry(ctx, alias.AliasName, alias.TargetKeyId)
		switch {
		case err != nil:
			return nil, kmsErr.New("failed to process KMS key: %v", err)
		case entry != nil:
			err := p.setEntry(entry.PublicKey.Id, *entry)
			if err != nil {
				return nil, err
			}
		}
	}

	return &plugin.ConfigureResponse{}, nil
}

func (p *Plugin) GenerateKey(ctx context.Context, req *keymanager.GenerateKeyRequest) (*keymanager.GenerateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, kmsErr.New("key id is required")
	}
	if req.KeyType == keymanager.KeyType_UNSPECIFIED_KEY_TYPE {
		return nil, kmsErr.New("key type is required")
	}

	spireKeyID := req.KeyId

	newEntry, err := p.createKey(ctx, spireKeyID, req.KeyType)
	if err != nil {
		return nil, err
	}

	oldEntry, hasOldEntry := p.entry(spireKeyID)

	if !hasOldEntry {
		//create alias
		_, err = p.kmsClient.CreateAliasWithContext(ctx, &kms.CreateAliasInput{
			AliasName:   aws.String(newEntry.Alias),
			TargetKeyId: &newEntry.KMSKeyID,
		})
		if err != nil {
			return nil, kmsErr.New("failed to create alias: %v", err)
		}

	} else {
		//update alias
		_, err = p.kmsClient.UpdateAliasWithContext(ctx, &kms.UpdateAliasInput{
			AliasName:   aws.String(newEntry.Alias),
			TargetKeyId: &newEntry.KMSKeyID,
		})
		if err != nil {
			return nil, kmsErr.New("failed to update alias: %v", err)
		}

		go func() {
			//schedule delete
			_, err = p.kmsClient.ScheduleKeyDeletionWithContext(ctx, &kms.ScheduleKeyDeletionInput{
				KeyId:               &oldEntry.KMSKeyID,
				PendingWindowInDays: aws.Int64(7),
			})
			if err != nil {
				p.log.With(keyIDTag, &oldEntry.KMSKeyID).Error("It was not possible to schedule deletion for key: %v", err)
			}

		}()
	}

	err = p.setEntry(spireKeyID, newEntry)
	if err != nil {
		return nil, err
	}

	return &keymanager.GenerateKeyResponse{
		PublicKey: clonePublicKey(newEntry.PublicKey),
	}, nil

}

func (p *Plugin) SignData(ctx context.Context, req *keymanager.SignDataRequest) (*keymanager.SignDataResponse, error) {
	if req.KeyId == "" {
		return nil, kmsErr.New("key id is required")
	}
	if req.SignerOpts == nil {
		return nil, kmsErr.New("signer opts is required")
	}

	keyEntry, hasKey := p.entry(req.KeyId)
	if !hasKey {
		return nil, kmsErr.New("no such key %q", req.KeyId)
	}

	signingAlgo, err := signingAlgorithmForKMS(keyEntry.PublicKey.Type, req.SignerOpts)
	if err != nil {
		return nil, err
	}

	signResp, err := p.kmsClient.SignWithContext(ctx, &kms.SignInput{
		KeyId:            &keyEntry.Alias,
		Message:          req.Data,
		MessageType:      aws.String(kms.MessageTypeDigest),
		SigningAlgorithm: aws.String(signingAlgo),
	})
	if err != nil {
		return nil, kmsErr.New("failed to sign: %v", err)
	}

	return &keymanager.SignDataResponse{Signature: signResp.Signature}, nil
}

func (p *Plugin) GetPublicKey(ctx context.Context, req *keymanager.GetPublicKeyRequest) (*keymanager.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, kmsErr.New("key id is required")
	}

	entry, ok := p.entry(req.KeyId)
	if !ok {
		return nil, kmsErr.New("no such key %q", req.KeyId)
	}

	return &keymanager.GetPublicKeyResponse{
		PublicKey: clonePublicKey(entry.PublicKey),
	}, nil

}

func (p *Plugin) GetPublicKeys(context.Context, *keymanager.GetPublicKeysRequest) (*keymanager.GetPublicKeysResponse, error) {
	var keys []*keymanager.PublicKey
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, key := range p.entries {
		keys = append(keys, clonePublicKey(key.PublicKey))
	}

	return &keymanager.GetPublicKeysResponse{PublicKeys: keys}, nil
}

func (p *Plugin) GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}

func (p *Plugin) setEntry(spireKeyID string, entry keyEntry) error {
	if spireKeyID == "" {
		return kmsErr.New("spireKeyID is required")
	}
	if entry.KMSKeyID == "" {
		return kmsErr.New("KMSKeyID is required")
	}
	if entry.Alias == "" {
		return kmsErr.New("Alias is required")
	}
	if entry.PublicKey == nil {
		return kmsErr.New("PublicKey is required")
	}
	if entry.PublicKey.Id == "" {
		return kmsErr.New("PublicKey.Id is required")
	}
	if entry.PublicKey.Type == keymanager.KeyType_UNSPECIFIED_KEY_TYPE {
		return kmsErr.New("PublicKey.Type is required")
	}
	if entry.PublicKey.PkixData == nil || len(entry.PublicKey.PkixData) == 0 {
		return kmsErr.New("PublicKey.PkixData is required")
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.entries[spireKeyID] = entry
	return nil
}

func (p *Plugin) entry(spireKeyID string) (keyEntry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	value, hasKey := p.entries[spireKeyID]
	return value, hasKey
}

func (p *Plugin) createKey(ctx context.Context, spireKeyID string, keyType keymanager.KeyType) (keyEntry, error) {
	res := keyEntry{}
	description := descriptionFromSpireKeyID(spireKeyID)
	keySpec, err := keySpecFromKeyType(keyType)
	if err != nil {
		return res, err
	}

	createKeyInput := &kms.CreateKeyInput{
		Description:           aws.String(description),
		KeyUsage:              aws.String(kms.KeyUsageTypeSignVerify),
		CustomerMasterKeySpec: aws.String(keySpec),
	}

	key, err := p.kmsClient.CreateKeyWithContext(ctx, createKeyInput)
	if err != nil {
		return res, kmsErr.New("failed to create key: %v", err)
	}

	pub, err := p.kmsClient.GetPublicKeyWithContext(ctx, &kms.GetPublicKeyInput{KeyId: key.KeyMetadata.KeyId})
	if err != nil {
		return res, kmsErr.New("failed to get public key: %v", err)
	}

	res = keyEntry{
		KMSKeyID: *pub.KeyId,
		Alias:    aliasFromSpireKeyID(spireKeyID),
		PublicKey: &keymanager.PublicKey{
			Id:       spireKeyID,
			Type:     keyType,
			PkixData: pub.PublicKey,
		},
	}

	return res, nil
}

func (p *Plugin) buildKeyEntry(ctx context.Context, alias *string, awsKeyID *string) (*keyEntry, error) {
	describeResp, err := p.kmsClient.DescribeKeyWithContext(ctx, &kms.DescribeKeyInput{KeyId: awsKeyID})
	if err != nil {
		return nil, kmsErr.New("failed to describe key: %v", err)
	}

	if *describeResp.KeyMetadata.Enabled == false {
		p.log.With(keyIDTag, awsKeyID).Debug("Skipping disabled key")
		return nil, nil
	}

	spireKeyID, err := spireKeyIDFromAlias(*alias)
	if err != nil {
		p.log.With(keyIDTag, awsKeyID).Debug("Skipping key: %v", err)
		return nil, nil
	}

	keyType, err := keyTypeFromKeySpec(*describeResp.KeyMetadata.CustomerMasterKeySpec)
	if err != nil {
		p.log.With(keyIDTag, awsKeyID).Warn("Skipping key: %v", err)
		return nil, nil
	}

	getPublicKeyResp, err := p.kmsClient.GetPublicKeyWithContext(ctx, &kms.GetPublicKeyInput{KeyId: awsKeyID})
	if err != nil {
		return nil, kmsErr.New("failed to get public key: %v", err)
	}

	return &keyEntry{
		KMSKeyID: *awsKeyID,
		Alias:    *alias,
		PublicKey: &keymanager.PublicKey{
			Id:       spireKeyID,
			Type:     keyType,
			PkixData: getPublicKeyResp.PublicKey,
		},
	}, err
}

func spireKeyIDFromAlias(alias string) (string, error) {
	tokens := strings.SplitAfter(alias, keyPrefix)
	if len(tokens) != 2 {
		return "", kmsErr.New("alias does not contain SPIRE prefix")
	}

	return tokens[1], nil
}

func aliasFromSpireKeyID(spireKeyID string) string {
	return fmt.Sprintf("%v%v%v", aliasPrefix, keyPrefix, spireKeyID)
}

func descriptionFromSpireKeyID(spireKeyID string) string {
	return fmt.Sprintf("%v%v", keyPrefix, spireKeyID)
}

// validateConfig returns an error if any configuration provided does not meet acceptable criteria
func validateConfig(c string) (*Config, error) {
	config := new(Config)

	if err := hcl.Decode(config, c); err != nil {
		return nil, kmsErr.New("unable to decode configuration: %v", err)
	}

	if config.AccessKeyID == "" {
		return nil, kmsErr.New("configuration is missing an access key id")
	}

	if config.SecretAccessKey == "" {
		return nil, kmsErr.New("configuration is missing a secret access key")
	}

	if config.Region == "" {
		return nil, kmsErr.New("configuration is missing a region")
	}

	return config, nil
}

func signingAlgorithmForKMS(keyType keymanager.KeyType, signerOpts interface{}) (string, error) {
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
			return "", kmsErr.New("PSS options are required")
		}
		hashAlgo = opts.PssOptions.HashAlgorithm
		isPSS = true
		// opts.PssOptions.SaltLength is handled by KMS. The salt length matches the bits of the hashing algorithm.
	default:
		return "", kmsErr.New("unsupported signer opts type %T", opts)
	}

	isRSA := keyType == keymanager.KeyType_RSA_2048 || keyType == keymanager.KeyType_RSA_4096

	switch {
	case hashAlgo == keymanager.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM:
		return "", kmsErr.New("hash algorithm is required")
	case keyType == keymanager.KeyType_EC_P256 && hashAlgo == keymanager.HashAlgorithm_SHA256:
		return kms.SigningAlgorithmSpecEcdsaSha256, nil
	case keyType == keymanager.KeyType_EC_P384 && hashAlgo == keymanager.HashAlgorithm_SHA384:
		return kms.SigningAlgorithmSpecEcdsaSha384, nil
	case isRSA && !isPSS && hashAlgo == keymanager.HashAlgorithm_SHA256:
		return kms.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
	case isRSA && !isPSS && hashAlgo == keymanager.HashAlgorithm_SHA384:
		return kms.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
	case isRSA && !isPSS && hashAlgo == keymanager.HashAlgorithm_SHA512:
		return kms.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
	case isRSA && isPSS && hashAlgo == keymanager.HashAlgorithm_SHA256:
		return kms.SigningAlgorithmSpecRsassaPssSha256, nil
	case isRSA && isPSS && hashAlgo == keymanager.HashAlgorithm_SHA384:
		return kms.SigningAlgorithmSpecRsassaPssSha384, nil
	case isRSA && isPSS && hashAlgo == keymanager.HashAlgorithm_SHA512:
		return kms.SigningAlgorithmSpecRsassaPssSha512, nil
	default:
		return "", kmsErr.New("unsupported combination of keytype: %v and hashing algorithm: %v", keyType, hashAlgo)
	}
}

func keyTypeFromKeySpec(keySpec string) (keymanager.KeyType, error) {
	switch keySpec {
	case kms.CustomerMasterKeySpecRsa2048:
		return keymanager.KeyType_RSA_2048, nil
	case kms.CustomerMasterKeySpecRsa4096:
		return keymanager.KeyType_RSA_4096, nil
	case kms.CustomerMasterKeySpecEccNistP256:
		return keymanager.KeyType_EC_P256, nil
	case kms.CustomerMasterKeySpecEccNistP384:
		return keymanager.KeyType_EC_P384, nil
	default:
		return keymanager.KeyType_UNSPECIFIED_KEY_TYPE, kmsErr.New("unsupported key spec: %v", keySpec)
	}

}

func keySpecFromKeyType(keyType keymanager.KeyType) (string, error) {
	switch keyType {
	case keymanager.KeyType_RSA_1024:
		return "", kmsErr.New("unsupported key type: KeyType_RSA_1024")
	case keymanager.KeyType_RSA_2048:
		return kms.CustomerMasterKeySpecRsa2048, nil
	case keymanager.KeyType_RSA_4096:
		return kms.CustomerMasterKeySpecRsa4096, nil
	case keymanager.KeyType_EC_P256:
		return kms.CustomerMasterKeySpecEccNistP256, nil
	case keymanager.KeyType_EC_P384:
		return kms.CustomerMasterKeySpecEccNistP384, nil
	default:
		return "", kmsErr.New("unknown key type")
	}
}

func clonePublicKey(publicKey *keymanager.PublicKey) *keymanager.PublicKey {
	return proto.Clone(publicKey).(*keymanager.PublicKey)
}
