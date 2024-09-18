package awskms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type kmsClientFake struct {
	t                      *testing.T
	store                  fakeStore
	mu                     sync.RWMutex
	testKeys               testkey.Keys
	validAliasName         *regexp.Regexp
	createKeyErr           error
	describeKeyErr         error
	getPublicKeyErr        error
	listAliasesErr         error
	createAliasErr         error
	updateAliasErr         error
	scheduleKeyDeletionErr error
	signErr                error
	listKeysErr            error
	deleteAliasErr         error

	expectedKeyPolicy *string
}

type stsClientFake struct {
	account string
	arn     string
	err     string
}

func newKMSClientFake(t *testing.T, c *clock.Mock) *kmsClientFake {
	return &kmsClientFake{
		t:     t,
		store: newFakeStore(c),

		// Valid KMS alias name must match the expression below:
		// https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateAlias.html#API_CreateAlias_RequestSyntax
		validAliasName: regexp.MustCompile(`^alias/[a-zA-Z0-9/_-]+$`),
	}
}

func newSTSClientFake() *stsClientFake {
	return &stsClientFake{}
}

func (s *stsClientFake) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if s.err != "" {
		return nil, errors.New(s.err)
	}

	return &sts.GetCallerIdentityOutput{
		Account: &s.account,
		Arn:     &s.arn,
	}, nil
}

func (s *stsClientFake) setGetCallerIdentityErr(err string) {
	s.err = err
}

func (s *stsClientFake) setGetCallerIdentityAccount(account string) {
	s.account = account
}

func (s *stsClientFake) setGetCallerIdentityArn(arn string) {
	s.arn = arn
}

func (k *kmsClientFake) setExpectedKeyPolicy(keyPolicy *string) {
	k.expectedKeyPolicy = keyPolicy
}

func (k *kmsClientFake) CreateKey(_ context.Context, input *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.createKeyErr != nil {
		return nil, k.createKeyErr
	}

	switch k.expectedKeyPolicy {
	case nil:
		require.Nil(k.t, input.Policy)
	default:
		require.Equal(k.t, *k.expectedKeyPolicy, *input.Policy)
	}

	var privateKey crypto.Signer
	switch input.KeySpec {
	case types.KeySpecEccNistP256:
		privateKey = k.testKeys.NewEC256(k.t)
	case types.KeySpecEccNistP384:
		privateKey = k.testKeys.NewEC384(k.t)
	case types.KeySpecRsa2048:
		privateKey = k.testKeys.NewRSA2048(k.t)
	case types.KeySpecRsa4096:
		privateKey = k.testKeys.NewRSA4096(k.t)
	default:
		return nil, fmt.Errorf("unknown key type %q", input.KeySpec)
	}

	pkixData, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, err
	}

	keyEntry := &fakeKeyEntry{
		Description:  input.Description,
		CreationDate: aws.Time(time.Unix(0, 0)),
		PublicKey:    pkixData,
		privateKey:   privateKey,
		KeySpec:      input.KeySpec,
		Enabled:      true,
	}

	k.store.SaveKeyEntry(keyEntry)

	return &kms.CreateKeyOutput{
		KeyMetadata: &types.KeyMetadata{
			KeyId:        keyEntry.KeyID,
			Arn:          keyEntry.Arn,
			Description:  keyEntry.Description,
			CreationDate: keyEntry.CreationDate,
		},
	}, nil
}

func (k *kmsClientFake) DescribeKey(_ context.Context, input *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.describeKeyErr != nil {
		return nil, k.describeKeyErr
	}

	keyEntry, err := k.store.FetchKeyEntry(*input.KeyId)
	if err != nil {
		return nil, err
	}

	return &kms.DescribeKeyOutput{
		KeyMetadata: &types.KeyMetadata{
			KeyId:        keyEntry.KeyID,
			Arn:          keyEntry.Arn,
			KeySpec:      keyEntry.KeySpec,
			Enabled:      keyEntry.Enabled,
			Description:  keyEntry.Description,
			CreationDate: keyEntry.CreationDate,
		},
	}, nil
}

func (k *kmsClientFake) GetPublicKey(_ context.Context, input *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.getPublicKeyErr != nil {
		return nil, k.getPublicKeyErr
	}

	keyEntry, err := k.store.FetchKeyEntry(*input.KeyId)
	if err != nil {
		return nil, err
	}

	return &kms.GetPublicKeyOutput{
		KeyId:     keyEntry.KeyID,
		PublicKey: keyEntry.PublicKey,
	}, nil
}

func (k *kmsClientFake) ListAliases(_ context.Context, input *kms.ListAliasesInput, _ ...func(*kms.Options)) (*kms.ListAliasesOutput, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.listAliasesErr != nil {
		return nil, k.listAliasesErr
	}

	if input.KeyId != nil {
		keyEntry, err := k.store.FetchKeyEntry(*input.KeyId)
		switch {
		case err != nil:
			return nil, err
		case keyEntry.AliasName != nil:
			aliasesResp := []types.AliasListEntry{{
				AliasName:       keyEntry.AliasName,
				AliasArn:        aws.String(aliasArnFromAliasName(*keyEntry.AliasName)),
				TargetKeyId:     keyEntry.KeyID,
				LastUpdatedDate: keyEntry.AliasLastUpdatedDate,
			}}
			return &kms.ListAliasesOutput{Aliases: aliasesResp}, nil
		default:
			return &kms.ListAliasesOutput{Aliases: []types.AliasListEntry{}}, nil
		}
	}

	var aliasesResp []types.AliasListEntry
	for _, alias := range k.store.ListAliases() {
		aliasesResp = append(aliasesResp, types.AliasListEntry{
			AliasName:       alias.AliasName,
			AliasArn:        aws.String(aliasArnFromAliasName(*alias.AliasName)),
			TargetKeyId:     alias.KeyEntry.KeyID,
			LastUpdatedDate: alias.KeyEntry.AliasLastUpdatedDate,
		})
	}

	return &kms.ListAliasesOutput{Aliases: aliasesResp}, nil
}

func (k *kmsClientFake) ScheduleKeyDeletion(_ context.Context, input *kms.ScheduleKeyDeletionInput, _ ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.scheduleKeyDeletionErr != nil {
		return nil, k.scheduleKeyDeletionErr
	}

	k.store.DeleteKeyEntry(*input.KeyId)

	return &kms.ScheduleKeyDeletionOutput{}, nil
}

func (k *kmsClientFake) Sign(_ context.Context, input *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.signErr != nil {
		return nil, k.signErr
	}

	if input.MessageType != types.MessageTypeDigest {
		return nil, status.Error(codes.InvalidArgument, "plugin should be signing over a digest")
	}

	entry, err := k.store.FetchKeyEntry(*input.KeyId)
	if err != nil {
		return nil, err
	}

	signRSA := func(opts crypto.SignerOpts) ([]byte, error) {
		if _, ok := entry.privateKey.(*rsa.PrivateKey); !ok {
			return nil, status.Errorf(codes.InvalidArgument, "invalid signing algorithm %q for RSA key", input.SigningAlgorithm)
		}
		return entry.privateKey.Sign(rand.Reader, input.Message, opts)
	}
	signECDSA := func(opts crypto.SignerOpts) ([]byte, error) {
		if _, ok := entry.privateKey.(*ecdsa.PrivateKey); !ok {
			return nil, status.Errorf(codes.InvalidArgument, "invalid signing algorithm %q for ECDSA key", input.SigningAlgorithm)
		}
		return entry.privateKey.Sign(rand.Reader, input.Message, opts)
	}

	var signature []byte
	switch input.SigningAlgorithm {
	case types.SigningAlgorithmSpecRsassaPssSha256:
		signature, err = signRSA(&rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash})
	case types.SigningAlgorithmSpecRsassaPssSha384:
		signature, err = signRSA(&rsa.PSSOptions{Hash: crypto.SHA384, SaltLength: rsa.PSSSaltLengthEqualsHash})
	case types.SigningAlgorithmSpecRsassaPssSha512:
		signature, err = signRSA(&rsa.PSSOptions{Hash: crypto.SHA512, SaltLength: rsa.PSSSaltLengthEqualsHash})
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha256:
		signature, err = signRSA(crypto.SHA256)
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha384:
		signature, err = signRSA(crypto.SHA384)
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha512:
		signature, err = signRSA(crypto.SHA512)
	case types.SigningAlgorithmSpecEcdsaSha256:
		signature, err = signECDSA(crypto.SHA256)
	case types.SigningAlgorithmSpecEcdsaSha384:
		signature, err = signECDSA(crypto.SHA384)
	case types.SigningAlgorithmSpecEcdsaSha512:
		signature, err = signECDSA(crypto.SHA512)
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported signing algorithm: %s", input.SigningAlgorithm)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to sign digest: %v", err)
	}

	return &kms.SignOutput{Signature: signature}, nil
}

func (k *kmsClientFake) CreateAlias(_ context.Context, input *kms.CreateAliasInput, _ ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.createAliasErr != nil {
		return nil, k.createAliasErr
	}

	if !k.validAliasName.MatchString(*input.AliasName) {
		return nil, fmt.Errorf("unsupported KMS alias name: %v", *input.AliasName)
	}

	err := k.store.SaveAlias(*input.TargetKeyId, *input.AliasName)
	if err != nil {
		return nil, err
	}

	return &kms.CreateAliasOutput{}, nil
}

func (k *kmsClientFake) UpdateAlias(_ context.Context, input *kms.UpdateAliasInput, _ ...func(*kms.Options)) (*kms.UpdateAliasOutput, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.updateAliasErr != nil {
		return nil, k.updateAliasErr
	}

	err := k.store.SaveAlias(*input.TargetKeyId, *input.AliasName)
	if err != nil {
		return nil, err
	}

	return &kms.UpdateAliasOutput{}, nil
}

func (k *kmsClientFake) ListKeys(context.Context, *kms.ListKeysInput, ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.listKeysErr != nil {
		return nil, k.listKeysErr
	}

	var keysResp []types.KeyListEntry
	for _, keyEntry := range k.store.ListKeyEntries() {
		keysResp = append(keysResp, types.KeyListEntry{
			KeyArn: keyEntry.Arn,
			KeyId:  keyEntry.KeyID,
		})
	}

	return &kms.ListKeysOutput{Keys: keysResp}, nil
}

func (k *kmsClientFake) DeleteAlias(_ context.Context, params *kms.DeleteAliasInput, _ ...func(*kms.Options)) (*kms.DeleteAliasOutput, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.deleteAliasErr != nil {
		return nil, k.deleteAliasErr
	}

	k.store.DeleteAlias(*params.AliasName)
	return nil, nil
}

func (k *kmsClientFake) setEntries(entries []fakeKeyEntry) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if entries == nil {
		return
	}
	for _, e := range entries {
		if e.KeyID != nil {
			newEntry := e
			k.store.SaveKeyEntry(&newEntry)
		}
		if e.AliasName != nil {
			err := k.store.SaveAlias(*e.KeyID, *e.AliasName)
			if err != nil {
				k.t.Error(err)
			}
		}
	}
}

func (k *kmsClientFake) setCreateKeyErr(fakeError string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if fakeError != "" {
		k.createKeyErr = errors.New(fakeError)
	}
}
func (k *kmsClientFake) setDescribeKeyErr(fakeError string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if fakeError != "" {
		k.describeKeyErr = errors.New(fakeError)
	}
}

func (k *kmsClientFake) setgetPublicKeyErr(fakeError string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if fakeError != "" {
		k.getPublicKeyErr = errors.New(fakeError)
	}
}

func (k *kmsClientFake) setListAliasesErr(fakeError string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if fakeError != "" {
		k.listAliasesErr = errors.New(fakeError)
	}
}

func (k *kmsClientFake) setCreateAliasesErr(fakeError string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if fakeError != "" {
		k.createAliasErr = errors.New(fakeError)
	}
}

func (k *kmsClientFake) setUpdateAliasErr(fakeError string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if fakeError != "" {
		k.updateAliasErr = errors.New(fakeError)
	}
}

func (k *kmsClientFake) setScheduleKeyDeletionErr(fakeError error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if fakeError != nil {
		k.scheduleKeyDeletionErr = fakeError
	}
}

func (k *kmsClientFake) setSignDataErr(fakeError string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if fakeError != "" {
		k.signErr = errors.New(fakeError)
	}
}

func (k *kmsClientFake) setListKeysErr(fakeError string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if fakeError != "" {
		k.listKeysErr = errors.New(fakeError)
	}
}

func (k *kmsClientFake) setDeleteAliasErr(fakeError string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if fakeError != "" {
		k.deleteAliasErr = errors.New(fakeError)
	}
}

const (
	fakeKeyArnPrefix   = "arn:aws:kms:region:1234:key/"
	fakeAliasArnPrefix = "arn:aws:kms:region:1234:"
)

type fakeStore struct {
	keyEntries map[string]*fakeKeyEntry // don't user ara for key
	aliases    map[string]fakeAlias     // don't user ara for key
	mu         sync.RWMutex
	nextID     int
	clk        *clock.Mock
}

func newFakeStore(c *clock.Mock) fakeStore {
	return fakeStore{
		keyEntries: make(map[string]*fakeKeyEntry),
		aliases:    make(map[string]fakeAlias),
		clk:        c,
	}
}

type fakeKeyEntry struct {
	KeyID                *string
	Arn                  *string
	Description          *string
	CreationDate         *time.Time
	AliasName            *string // Only one alias per key. "Real" KMS supports many aliases per key
	AliasLastUpdatedDate *time.Time
	PublicKey            []byte
	privateKey           crypto.Signer
	Enabled              bool
	KeySpec              types.KeySpec
}

type fakeAlias struct {
	AliasName *string
	AliasArn  *string
	KeyEntry  *fakeKeyEntry
}

func (fs *fakeStore) SaveKeyEntry(input *fakeKeyEntry) {
	if input.KeyID == nil {
		input.KeyID = aws.String(strconv.Itoa(fs.nextID))
		fs.nextID++
	}
	input.Arn = aws.String(arnFromKeyID(*input.KeyID))

	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.keyEntries[*input.KeyID] = input
}

func (fs *fakeStore) DeleteKeyEntry(keyID string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	delete(fs.keyEntries, keyID)
	delete(fs.keyEntries, keyIDFromArn(keyID))

	for k, v := range fs.aliases {
		if *v.KeyEntry.KeyID == keyID || *v.KeyEntry.Arn == keyID {
			delete(fs.aliases, k)
		}
	}
}

func (fs *fakeStore) SaveAlias(targetKeyID, aliasName string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	keyEntry, err := fs.fetchKeyEntry(targetKeyID)
	if err != nil {
		return err
	}

	keyEntry.AliasName = &aliasName
	keyEntry.AliasLastUpdatedDate = aws.Time(fs.clk.Now())

	fs.aliases[aliasName] = fakeAlias{
		AliasName: aws.String(aliasName),
		AliasArn:  aws.String(aliasArnFromAliasName(aliasName)),
		KeyEntry:  keyEntry,
	}

	return nil
}

func (fs *fakeStore) DeleteAlias(aliasName string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	delete(fs.aliases, aliasName)
}

func (fs *fakeStore) ListKeyEntries() []fakeKeyEntry {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	var keyEntries []fakeKeyEntry
	for _, v := range fs.keyEntries {
		keyEntries = append(keyEntries, *v)
	}
	return keyEntries
}

func (fs *fakeStore) ListAliases() []fakeAlias {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	var aliases []fakeAlias
	for _, v := range fs.aliases {
		aliases = append(aliases, fakeAlias{
			AliasName: v.AliasName,
			AliasArn:  v.AliasArn,
			KeyEntry: &fakeKeyEntry{
				KeyID:                v.KeyEntry.KeyID,
				Arn:                  v.KeyEntry.Arn,
				Description:          v.KeyEntry.Description,
				CreationDate:         v.KeyEntry.CreationDate,
				AliasName:            v.KeyEntry.AliasName,
				AliasLastUpdatedDate: v.KeyEntry.AliasLastUpdatedDate,
				PublicKey:            v.KeyEntry.PublicKey,
				privateKey:           v.KeyEntry.privateKey,
				Enabled:              v.KeyEntry.Enabled,
				KeySpec:              v.KeyEntry.KeySpec,
			},
		})
	}
	return aliases
}

func (fs *fakeStore) FetchKeyEntry(id string) (*fakeKeyEntry, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.fetchKeyEntry(id)
}

func (fs *fakeStore) fetchKeyEntry(id string) (*fakeKeyEntry, error) {
	keyEntry, ok := fs.keyEntries[id]
	if ok {
		return keyEntry, nil
	}

	keyEntry, ok = fs.keyEntries[keyIDFromArn(id)]
	if ok {
		return keyEntry, nil
	}

	aliasEntry, ok := fs.aliases[id]
	if ok {
		return aliasEntry.KeyEntry, nil
	}

	aliasEntry, ok = fs.aliases[aliasNameFromArn(id)]
	if ok {
		return aliasEntry.KeyEntry, nil
	}

	return &fakeKeyEntry{}, fmt.Errorf("no such key %q", id)
}

func aliasArnFromAliasName(aliasName string) string {
	return fakeAliasArnPrefix + aliasName
}

func aliasNameFromArn(arn string) string {
	return strings.TrimPrefix(arn, fakeAliasArnPrefix)
}

func arnFromKeyID(keyID string) string {
	return fakeKeyArnPrefix + keyID
}

func keyIDFromArn(arn string) string {
	return strings.TrimPrefix(arn, fakeKeyArnPrefix)
}
