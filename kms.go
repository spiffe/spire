package kms

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/keymanager"
	"github.com/zeebo/errs"
)

// Major TODOS:
// - input validations
// - config validation
// - error embellishment and wrapping
// - move kmsClient into another file plus the init of it. Similar to https://github.com/spiffe/spire/blob/cff72a54c3d3a688d789fb43fd8c5ee830be92e3/pkg/server/plugin/upstreamauthority/awspca/pca_client.go
// - kms client fake
// - testing

var (
	kmsErr = errs.Class("kms")
)

const (
	keyPrefix = "SPIRE_SERVER_KEY:"
)

type keyEntry struct {
	AwsKeyID     string
	CreationDate time.Time
	PublicKey    *keymanager.PublicKey
}

type Plugin struct {
	log       hclog.Logger
	mu        sync.RWMutex
	entries   map[string]*keyEntry
	kmsClient kmsClient
}

type Config struct {
	AccessKeyID     string `hcl:"access_key_id" json:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key" json:"secret_access_key"`
	Region          string `hcl:"region" json:"region"`
}

func New() *Plugin {
	return &Plugin{
		entries: make(map[string]*keyEntry),
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
		return nil, err
	}

	// TODO: pagination
	listKeysResp, err := p.kmsClient.ListKeysWithContext(ctx, &kms.ListKeysInput{})
	if err != nil {
		return nil, err
	}

	for _, key := range listKeysResp.Keys {
		err := p.processKMSKey(ctx, key.KeyId)
		if err != nil {
			p.log.Error("Failed to process kms key.", "KeyId", *key.KeyId, "error", err)
		}
	}

	return &plugin.ConfigureResponse{}, nil
}

func (p *Plugin) GenerateKey(ctx context.Context, req *keymanager.GenerateKeyRequest) (*keymanager.GenerateKeyResponse, error) {
	spireKeyID := req.KeyId
	description := fmt.Sprintf("%v%v", keyPrefix, spireKeyID)
	keySpec, err := keySpecFromKeyType(req.KeyType)
	if err != nil {
		return nil, err
	}

	createKeyInput := &kms.CreateKeyInput{
		Description:           aws.String(description), //TODO: check using alias instead
		KeyUsage:              aws.String(kms.KeyUsageTypeSignVerify),
		CustomerMasterKeySpec: aws.String(keySpec),
		//TODO: look into policies
	}

	key, err := p.kmsClient.CreateKeyWithContext(ctx, createKeyInput)
	if err != nil {
		return nil, err
	}

	pub, err := p.kmsClient.GetPublicKeyWithContext(ctx, &kms.GetPublicKeyInput{KeyId: key.KeyMetadata.KeyId})
	if err != nil {
		return nil, err
	}

	newEntry := &keyEntry{
		AwsKeyID:     *pub.KeyId,
		CreationDate: *key.KeyMetadata.CreationDate,
		PublicKey: &keymanager.PublicKey{
			Id:       spireKeyID,
			Type:     req.KeyType,
			PkixData: pub.PublicKey,
		},
	}

	oldEntry, hasOldEntry := p.entry(spireKeyID)
	ok := p.setEntry(spireKeyID, newEntry)

	// only delete if an old entry was replaced by a new one
	if hasOldEntry && ok {
		_, err := p.kmsClient.ScheduleKeyDeletionWithContext(ctx, &kms.ScheduleKeyDeletionInput{KeyId: &oldEntry.AwsKeyID})
		if err != nil {
			return nil, err
		}
	}

	return &keymanager.GenerateKeyResponse{PublicKey: newEntry.PublicKey}, nil
}

func (p *Plugin) SignData(ctx context.Context, req *keymanager.SignDataRequest) (*keymanager.SignDataResponse, error) {
	keyEntry, hasKey := p.entry(req.KeyId)
	if !hasKey {
		return nil, kmsErr.New("unable to find KeyId: %v", req.KeyId)
	}

	signingAlgo, err := signingAlgorithmForKMS(keyEntry.PublicKey.Type, req.SignerOpts)
	if err != nil {
		return nil, err
	}

	signResp, err := p.kmsClient.SignWithContext(ctx, &kms.SignInput{
		KeyId:            &keyEntry.AwsKeyID,
		Message:          req.Data,
		MessageType:      aws.String(kms.MessageTypeDigest),
		SigningAlgorithm: aws.String(signingAlgo),
	})
	if err != nil {
		return nil, err
	}

	return &keymanager.SignDataResponse{Signature: signResp.Signature}, nil
}

func (p *Plugin) GetPublicKey(ctx context.Context, req *keymanager.GetPublicKeyRequest) (*keymanager.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, kmsErr.New("KeyId is required")
	}

	resp := new(keymanager.GetPublicKeyResponse)

	e, ok := p.entry(req.KeyId)
	if !ok {
		//TODO: isn't it better to return error?
		return resp, nil
	}

	//TODO: clone it
	resp.PublicKey = e.PublicKey
	return resp, nil
}

func (p *Plugin) GetPublicKeys(context.Context, *keymanager.GetPublicKeysRequest) (*keymanager.GetPublicKeysResponse, error) {
	keys := p.publicKeys()
	return &keymanager.GetPublicKeysResponse{PublicKeys: keys}, nil
}

func (p *Plugin) GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}

func (p *Plugin) setEntry(spireKeyID string, newEntry *keyEntry) bool {
	//TODO: validate new entry
	p.mu.Lock()
	defer p.mu.Unlock()
	oldEntry, hasKey := p.entries[spireKeyID]
	if hasKey && oldEntry.CreationDate.Unix() > newEntry.CreationDate.Unix() {
		//TODO: log this. Also when there is a key and it's updated
		return false
	}
	p.entries[spireKeyID] = newEntry
	return true
}

func (p *Plugin) entry(spireKeyID string) (*keyEntry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	value, hasKey := p.entries[spireKeyID]
	return value, hasKey
}

func (p *Plugin) publicKeys() []*keymanager.PublicKey {
	var keys []*keymanager.PublicKey

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, key := range p.entries {
		keys = append(keys, key.PublicKey)
	}
	return keys
}

func (p *Plugin) processKMSKey(ctx context.Context, awsKeyID *string) error {
	describeResp, err := p.kmsClient.DescribeKeyWithContext(ctx, &kms.DescribeKeyInput{KeyId: awsKeyID})
	if err != nil {
		return err
	}

	keyType, err := keyTypeFromKeySpec(*describeResp.KeyMetadata.CustomerMasterKeySpec)
	if err != nil {
		return err
	}

	if *describeResp.KeyMetadata.Enabled == true && strings.HasPrefix(*describeResp.KeyMetadata.Description, keyPrefix) {
		descSplit := strings.SplitAfter(*describeResp.KeyMetadata.Description, keyPrefix)
		spireKeyID := descSplit[1]
		getPublicKeyResp, err := p.kmsClient.GetPublicKeyWithContext(ctx, &kms.GetPublicKeyInput{KeyId: awsKeyID})
		if err != nil {
			return err
		}

		e := &keyEntry{
			AwsKeyID:     *awsKeyID,
			CreationDate: *describeResp.KeyMetadata.CreationDate,
			PublicKey: &keymanager.PublicKey{
				Id:       spireKeyID,
				Type:     keyType,
				PkixData: getPublicKeyResp.PublicKey,
			},
		}
		p.setEntry(spireKeyID, e) //TODO: check return value?
	}
	return nil
}

func validateConfig(c string) (*Config, error) {
	config := new(Config)
	if err := hcl.Decode(config, c); err != nil {
		return nil, kmsErr.New("unable to decode configuration: %v", err)
	}

	// TODO: validate
	// if config.SomeValue == "" {
	// 	return nil, errors.New("some_value is required")
	// }
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
			return "", kmsErr.New("PSS options are nil")
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
		return "", kmsErr.New("unsupported combo of keytype: %v and hashing algo: %v", keyType, hashAlgo)
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
		return keymanager.KeyType_UNSPECIFIED_KEY_TYPE, kmsErr.New("unsupported keyspec: %v", keySpec)
	}

}

func keySpecFromKeyType(keyType keymanager.KeyType) (string, error) {
	switch keyType {
	case keymanager.KeyType_RSA_1024:
		return "", kmsErr.New("unsupported")
	case keymanager.KeyType_RSA_2048:
		return kms.CustomerMasterKeySpecRsa2048, nil
	case keymanager.KeyType_RSA_4096:
		return kms.CustomerMasterKeySpecRsa4096, nil
	case keymanager.KeyType_EC_P256:
		return kms.CustomerMasterKeySpecEccNistP256, nil
	case keymanager.KeyType_EC_P384:
		return kms.CustomerMasterKeySpecEccNistP384, nil
	default:
		return "", kmsErr.New("unknown and unsupported")
	}
}
