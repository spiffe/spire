package awskms

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/spiffe/spire/test/testkey"
)

type fakeKeyEntry struct {
	KeyID      *string
	AliasName  *string
	PublicKey  []byte
	privateKey crypto.PrivateKey
	Enabled    bool
	KeySpec    types.CustomerMasterKeySpec
}

type kmsClientFake struct {
	t                      *testing.T
	aliases                map[string]fakeKeyEntry
	keyEntries             map[string]fakeKeyEntry
	mu                     sync.RWMutex
	nextID                 int
	createKeyErr           error
	describeKeyErr         error
	getPublicKeyErr        error
	listAliasesErr         error
	createAliasErr         error
	updateAliasErr         error
	scheduleKeyDeletionErr error
	signErr                error
}

func newKMSClientFake(t *testing.T) *kmsClientFake {
	return &kmsClientFake{
		t:          t,
		aliases:    make(map[string]fakeKeyEntry),
		keyEntries: make(map[string]fakeKeyEntry),
	}
}

func (k *kmsClientFake) CreateKey(ctx context.Context, input *kms.CreateKeyInput, opts ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	if k.createKeyErr != nil {
		return nil, k.createKeyErr
	}

	var privateKey crypto.PrivateKey
	var publicKey crypto.PublicKey

	switch input.CustomerMasterKeySpec {
	case types.CustomerMasterKeySpecEccNistP256:
		key := testkey.NewEC256(k.t)
		privateKey = key
		publicKey = &key.PublicKey
	case types.CustomerMasterKeySpecEccNistP384:
		key := testkey.NewEC384(k.t)
		privateKey = key
		publicKey = &key.PublicKey
	case types.CustomerMasterKeySpecRsa2048:
		key := testkey.NewRSA2048(k.t)
		privateKey = key
		publicKey = &key.PublicKey
	case types.CustomerMasterKeySpecRsa4096:
		key := testkey.NewRSA4096(k.t)
		privateKey = key
		publicKey = &key.PublicKey
	default:
		return nil, fmt.Errorf("unknown key type %q", input.CustomerMasterKeySpec)
	}

	pkixData, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	keyID := strconv.Itoa(k.nextID)
	k.nextID++

	keyEntry := fakeKeyEntry{
		KeyID:      &keyID,
		Enabled:    true,
		PublicKey:  pkixData,
		privateKey: privateKey,
		KeySpec:    input.CustomerMasterKeySpec,
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	k.keyEntries[getKeyArn(keyID)] = keyEntry

	return &kms.CreateKeyOutput{
		KeyMetadata: &types.KeyMetadata{
			KeyId: aws.String(keyID),
			Arn:   aws.String(getKeyArn(keyID)),
		},
	}, nil
}

func (k *kmsClientFake) DescribeKey(ctx context.Context, input *kms.DescribeKeyInput, opts ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if k.describeKeyErr != nil {
		return nil, k.describeKeyErr
	}

	k.mu.RLock()
	defer k.mu.RUnlock()
	keyEntry, err := k.getKeyEntry(*input.KeyId)
	if err != nil {
		return nil, err
	}

	return &kms.DescribeKeyOutput{
		KeyMetadata: &types.KeyMetadata{
			KeyId:                 keyEntry.KeyID,
			Arn:                   aws.String(getKeyArn(*keyEntry.KeyID)),
			CustomerMasterKeySpec: keyEntry.KeySpec,
			Enabled:               keyEntry.Enabled,
		},
	}, nil
}

func (k *kmsClientFake) GetPublicKey(ctx context.Context, input *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if k.getPublicKeyErr != nil {
		return nil, k.getPublicKeyErr
	}

	k.mu.RLock()
	defer k.mu.RUnlock()
	keyEntry, err := k.getKeyEntry(*input.KeyId)
	if err != nil {
		return nil, err
	}

	return &kms.GetPublicKeyOutput{
		KeyId:     keyEntry.KeyID,
		PublicKey: keyEntry.PublicKey,
	}, nil
}

func (k *kmsClientFake) ListAliases(ctw context.Context, input *kms.ListAliasesInput, opts ...func(*kms.Options)) (*kms.ListAliasesOutput, error) {
	if k.listAliasesErr != nil {
		return nil, k.listAliasesErr
	}

	k.mu.RLock()
	defer k.mu.RUnlock()
	var aliasesResp []types.AliasListEntry
	for _, keyEntry := range k.keyEntries {
		aliasesResp = append(aliasesResp, types.AliasListEntry{
			AliasName:   keyEntry.AliasName,
			AliasArn:    aws.String(getAliasArn(*keyEntry.AliasName)),
			TargetKeyId: keyEntry.KeyID,
		})
	}
	for _, keyEntry := range k.aliases {
		aliasesResp = append(aliasesResp, types.AliasListEntry{
			AliasName:   keyEntry.AliasName,
			AliasArn:    aws.String(getAliasArn(*keyEntry.AliasName)),
			TargetKeyId: keyEntry.KeyID,
		})
	}

	return &kms.ListAliasesOutput{Aliases: aliasesResp}, nil
}

func (k *kmsClientFake) ScheduleKeyDeletion(ctx context.Context, input *kms.ScheduleKeyDeletionInput, opts ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error) {
	if k.scheduleKeyDeletionErr != nil {
		return nil, k.scheduleKeyDeletionErr
	}

	return &kms.ScheduleKeyDeletionOutput{}, nil
}

func (k *kmsClientFake) Sign(ctx context.Context, input *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error) {
	if k.signErr != nil {
		return nil, k.signErr
	}

	k.mu.RLock()
	defer k.mu.RUnlock()
	_, err := k.getKeyEntry(*input.KeyId)
	if err != nil {
		return nil, err
	}

	//TODO: do actual signing
	return &kms.SignOutput{Signature: input.Message}, nil
}

func (k *kmsClientFake) CreateAlias(ctx context.Context, input *kms.CreateAliasInput, opts ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
	if k.createAliasErr != nil {
		return nil, k.createAliasErr
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	keyEntry, err := k.getKeyEntry(*input.TargetKeyId)
	if err != nil {
		return nil, err
	}
	k.aliases[*input.AliasName] = keyEntry

	return &kms.CreateAliasOutput{}, nil
}

func (k *kmsClientFake) UpdateAlias(ctw context.Context, input *kms.UpdateAliasInput, opts ...func(*kms.Options)) (*kms.UpdateAliasOutput, error) {
	if k.updateAliasErr != nil {
		return nil, k.updateAliasErr
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	//TODO: review logic
	keyEntry, err := k.getKeyEntry(*input.TargetKeyId)
	if err != nil {
		return nil, err
	}
	k.aliases[*input.AliasName] = keyEntry

	return &kms.UpdateAliasOutput{}, nil
}

func (k *kmsClientFake) setEntries(entries []fakeKeyEntry) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if entries == nil {
		return
	}
	for _, e := range entries {
		if e.KeyID != nil {
			k.keyEntries[getKeyArn(*e.KeyID)] = e
		}
		if e.AliasName != nil {
			k.aliases[getAliasArn(*e.AliasName)] = e
		}
	}
}

func (k *kmsClientFake) getKeyEntry(arn string) (fakeKeyEntry, error) {
	keyEntry, ok := k.aliases[arn]
	if ok {
		return keyEntry, nil
	}

	keyEntry, ok = k.keyEntries[arn]
	if ok {
		return keyEntry, nil
	}

	return fakeKeyEntry{}, fmt.Errorf("no such key %q", arn)
}

func (k *kmsClientFake) setCreateKeyErr(fakeError string) {
	if fakeError != "" {
		k.createKeyErr = errors.New(fakeError)
	}
}
func (k *kmsClientFake) setDescribeKeyErr(fakeError string) {
	if fakeError != "" {
		k.describeKeyErr = errors.New(fakeError)
	}
}

func (k *kmsClientFake) setgetPublicKeyErr(fakeError string) {
	if fakeError != "" {
		k.getPublicKeyErr = errors.New(fakeError)
	}
}

func (k *kmsClientFake) setListAliasesErr(fakeError string) {
	if fakeError != "" {
		k.listAliasesErr = errors.New(fakeError)
	}
}

func (k *kmsClientFake) setCreateAliasesErr(fakeError string) {
	if fakeError != "" {
		k.createAliasErr = errors.New(fakeError)
	}
}

func (k *kmsClientFake) setUpdateAliasesErr(fakeError string) {
	if fakeError != "" {
		k.updateAliasErr = errors.New(fakeError)
	}
}

func (k *kmsClientFake) setScheduleKeyDeletionErr(fakeError error) {
	if fakeError != nil {
		k.scheduleKeyDeletionErr = fakeError
	}
}

func (k *kmsClientFake) setSignDataErr(fakeError string) {
	if fakeError != "" {
		k.signErr = errors.New(fakeError)
	}
}

func getAliasArn(aliasName string) string {
	return "arn:aws:kms:region:1234:" + aliasName
}

func getKeyArn(keyID string) string {
	return "arn:aws:kms:region:1234:key/" + keyID
}
