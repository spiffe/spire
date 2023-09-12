package azurekeyvault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/andres-erbsen/clock"
	"github.com/spiffe/spire/test/testkey"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type kmsClientFake struct {
	t               *testing.T
	store           fakeStore
	vaultURI        string
	trustDomain     string
	serverID        string
	mu              sync.RWMutex
	createKeyErr    error
	deleteKeyErr    error
	updateKeyErr    error
	getKeyErr       error
	listKeysErr     error
	getPublicKeyErr error
	signErr         error
}

type fakeStore struct {
	fakeKeys   map[string]*fakeKeyEntry
	ec256Key   crypto.Signer
	ec384Key   crypto.Signer
	rsa2048Key crypto.Signer
	rsa4096Key crypto.Signer
	mu         sync.RWMutex
	clk        *clock.Mock
}

type fakeKeyEntry struct {
	KeyBundle  azkeys.KeyBundle
	PrivateKey crypto.Signer
}

func newKMSClientFake(t *testing.T, vaultURI, trustDomain, serverID string, c *clock.Mock) *kmsClientFake {
	return &kmsClientFake{
		t:           t,
		vaultURI:    vaultURI,
		trustDomain: trustDomain,
		serverID:    serverID,
		store:       newFakeStore(c, t),
	}
}

func newFakeStore(c *clock.Mock, t *testing.T) fakeStore {
	testKeys := new(testkey.Keys)
	return fakeStore{
		fakeKeys:   make(map[string]*fakeKeyEntry),
		clk:        c,
		ec256Key:   testKeys.NewEC256(t),
		ec384Key:   testKeys.NewEC384(t),
		rsa2048Key: testKeys.NewRSA2048(t),
		rsa4096Key: testKeys.NewRSA4096(t),
	}
}

func (fs *fakeStore) SaveKeyEntry(input *fakeKeyEntry) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.fakeKeys[input.KeyBundle.Key.KID.Name()] = input
}

func (fs *fakeStore) DeleteKeyEntry(keyName string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	delete(fs.fakeKeys, keyName)
}

func (k *kmsClientFake) setEntries(entries []fakeKeyEntry) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if entries == nil {
		return
	}
	for _, e := range entries {
		if e.KeyBundle.Key != nil && e.KeyBundle.Key.KID != nil && e.KeyBundle.Key.KID.Name() != "" {
			newEntry := e
			k.store.SaveKeyEntry(&newEntry)
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
func (k *kmsClientFake) setGetKeyErr(fakeError string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if fakeError != "" {
		k.getKeyErr = errors.New(fakeError)
	}
}

func (k *kmsClientFake) setGetPublicKeyErr(fakeError string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if fakeError != "" {
		k.getPublicKeyErr = errors.New(fakeError)
	}
}

func (k *kmsClientFake) setUpdateKeyErr(fakeError string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if fakeError != "" {
		k.updateKeyErr = errors.New(fakeError)
	}
}

func (k *kmsClientFake) setDeleteKeyErr(fakeError error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if fakeError != nil {
		k.deleteKeyErr = fakeError
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

func (k *kmsClientFake) CreateKey(_ context.Context, keyName string, parameters azkeys.CreateKeyParameters, _ *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.createKeyErr != nil {
		return azkeys.CreateKeyResponse{}, k.createKeyErr
	}

	var publicKey *azkeys.JSONWebKey
	var privateKey crypto.Signer
	keyOperations := getKeyOperations()
	kmsKeyID := path.Join(k.vaultURI, keyName)
	switch {
	case *parameters.Kty == azkeys.JSONWebKeyTypeEC && *parameters.Curve == azkeys.JSONWebKeyCurveNameP256:
		privateKey = k.store.ec256Key
		publicKey = toECKey(privateKey.Public(), kmsKeyID, *parameters.Curve, keyOperations)
	case *parameters.Kty == azkeys.JSONWebKeyTypeEC && *parameters.Curve == azkeys.JSONWebKeyCurveNameP384:
		privateKey = k.store.ec384Key
		publicKey = toECKey(privateKey.Public(), kmsKeyID, *parameters.Curve, keyOperations)
	case *parameters.Kty == azkeys.JSONWebKeyTypeRSA && *parameters.KeySize == 2048:
		privateKey = k.store.rsa2048Key
		publicKey = toRSAKey(privateKey.Public(), kmsKeyID, keyOperations)
	case *parameters.Kty == azkeys.JSONWebKeyTypeRSA && *parameters.KeySize == 4096:
		privateKey = k.store.rsa4096Key
		publicKey = toRSAKey(privateKey.Public(), kmsKeyID, keyOperations)
	default:
		return azkeys.CreateKeyResponse{}, fmt.Errorf("unknown key type %q", *parameters.Kty)
	}

	keyAttr := &azkeys.KeyAttributes{
		Enabled: to.Ptr(true),
		Created: to.Ptr(time.Now()),
		Updated: to.Ptr(time.Now()),
	}

	tags := make(map[string]*string)
	tags[tagNameServerTrustDomain] = to.Ptr(k.trustDomain)
	tags[tagNameServerID] = to.Ptr(k.serverID)

	keyBundle := &azkeys.KeyBundle{
		Attributes: keyAttr,
		Key:        publicKey,
		Tags:       tags,
	}

	keyEntry := &fakeKeyEntry{
		KeyBundle:  *keyBundle,
		PrivateKey: privateKey,
	}

	k.store.SaveKeyEntry(keyEntry)
	return azkeys.CreateKeyResponse{KeyBundle: *keyBundle}, nil
}

func (k *kmsClientFake) DeleteKey(_ context.Context, name string, _ *azkeys.DeleteKeyOptions) (azkeys.DeleteKeyResponse, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.deleteKeyErr != nil {
		return azkeys.DeleteKeyResponse{}, k.deleteKeyErr
	}
	keyEntry, err := k.store.fetchKeyEntry(name)
	if err != nil {
		return azkeys.DeleteKeyResponse{}, err
	}

	k.store.DeleteKeyEntry(keyEntry.KeyBundle.Key.KID.Name())

	deletedKeyBundle := azkeys.DeletedKeyBundle{
		Attributes: keyEntry.KeyBundle.Attributes,
		Key:        keyEntry.KeyBundle.Key,
	}

	return azkeys.DeleteKeyResponse{DeletedKeyBundle: deletedKeyBundle}, nil
}

func (k *kmsClientFake) UpdateKey(_ context.Context, name, _ string, _ azkeys.UpdateKeyParameters, _ *azkeys.UpdateKeyOptions) (azkeys.UpdateKeyResponse, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.updateKeyErr != nil {
		return azkeys.UpdateKeyResponse{}, k.updateKeyErr
	}
	keyEntry, err := k.store.fetchKeyEntry(name)
	if err != nil {
		return azkeys.UpdateKeyResponse{}, err
	}

	keyEntry.KeyBundle.Attributes.Updated = to.Ptr(k.store.clk.Now())
	k.store.SaveKeyEntry(keyEntry)

	keyBundle := &azkeys.KeyBundle{
		Attributes: keyEntry.KeyBundle.Attributes,
		Key:        keyEntry.KeyBundle.Key,
		Tags:       keyEntry.KeyBundle.Tags,
	}

	return azkeys.UpdateKeyResponse{KeyBundle: *keyBundle}, nil
}

func (k *kmsClientFake) GetKey(_ context.Context, keyName, _ string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.getKeyErr != nil {
		return azkeys.GetKeyResponse{}, k.getKeyErr
	}
	keyEntry, err := k.store.fetchKeyEntry(keyName)
	if err != nil {
		return azkeys.GetKeyResponse{}, err
	}
	keyBundle := &azkeys.KeyBundle{
		Attributes: keyEntry.KeyBundle.Attributes,
		Key:        keyEntry.KeyBundle.Key,
		Tags:       keyEntry.KeyBundle.Tags,
	}
	return azkeys.GetKeyResponse{KeyBundle: *keyBundle}, err
}

func (k *kmsClientFake) NewListKeysPager(_ *azkeys.ListKeysOptions) *runtime.Pager[azkeys.ListKeysResponse] {
	k.mu.RLock()
	defer k.mu.RUnlock()

	var listResp []*azkeys.KeyItem
	for _, keyEntry := range k.store.fetchKeyEntries() {
		listResp = append(listResp, &azkeys.KeyItem{
			Attributes: keyEntry.KeyBundle.Attributes,
			KID:        keyEntry.KeyBundle.Key.KID,
			Tags:       keyEntry.KeyBundle.Tags,
		})
	}

	return runtime.NewPager(runtime.PagingHandler[azkeys.ListKeysResponse]{
		More: func(page azkeys.ListKeysResponse) bool {
			return page.NextLink != nil && len(*page.NextLink) > 0
		},
		Fetcher: func(ctx context.Context, page *azkeys.ListKeysResponse) (azkeys.ListKeysResponse, error) {
			if k.listKeysErr != nil {
				return azkeys.ListKeysResponse{}, k.listKeysErr
			}

			return azkeys.ListKeysResponse{
				KeyListResult: azkeys.KeyListResult{
					NextLink: nil,
					Value:    listResp,
				},
			}, nil
		},
	})
}

func (k *kmsClientFake) Sign(_ context.Context, keyName, _ string, parameters azkeys.SignParameters, _ *azkeys.SignOptions) (azkeys.SignResponse, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.signErr != nil {
		return azkeys.SignResponse{}, k.signErr
	}

	entry, err := k.store.FetchKeyEntry(keyName)
	if err != nil {
		return azkeys.SignResponse{}, err
	}

	privateKey := entry.PrivateKey

	signRSA := func(opts crypto.SignerOpts) ([]byte, error) {
		if _, ok := privateKey.(*rsa.PrivateKey); !ok {
			return nil, status.Errorf(codes.InvalidArgument, "invalid signing algorithm %q for RSA key", *parameters.Algorithm)
		}
		return privateKey.(*rsa.PrivateKey).Sign(rand.Reader, parameters.Value, opts)
	}
	signECDSA := func() ([]byte, error) {
		if _, ok := privateKey.(*ecdsa.PrivateKey); !ok {
			return nil, status.Errorf(codes.InvalidArgument, "invalid signing algorithm %q for ECDSA key", *parameters.Algorithm)
		}

		key := privateKey.(*ecdsa.PrivateKey)
		// This is to produce an IEEE-P1363 encoded signature since that's how the azure signature is encoded
		curveBits := key.Curve.Params().BitSize
		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes++
		}
		r, s, err := ecdsa.Sign(rand.Reader, key, parameters.Value)
		if err != nil {
			return nil, fmt.Errorf("failed to sign data using ecdsa: %w", err)
		}

		rBytes := r.Bytes()
		rBytesPadded := make([]byte, keyBytes)
		copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)
		sBytes := s.Bytes()
		sBytesPadded := make([]byte, keyBytes)
		copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)
		return append(rBytesPadded, sBytesPadded...), nil
	}

	var signature []byte
	switch *parameters.Algorithm {
	case azkeys.JSONWebKeySignatureAlgorithmPS256:
		signature, err = signRSA(&rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash})
	case azkeys.JSONWebKeySignatureAlgorithmPS384:
		signature, err = signRSA(&rsa.PSSOptions{Hash: crypto.SHA384, SaltLength: rsa.PSSSaltLengthEqualsHash})
	case azkeys.JSONWebKeySignatureAlgorithmPS512:
		signature, err = signRSA(&rsa.PSSOptions{Hash: crypto.SHA512, SaltLength: rsa.PSSSaltLengthEqualsHash})
	case azkeys.JSONWebKeySignatureAlgorithmRS256:
		signature, err = signRSA(crypto.SHA256)
	case azkeys.JSONWebKeySignatureAlgorithmRS384:
		signature, err = signRSA(crypto.SHA384)
	case azkeys.JSONWebKeySignatureAlgorithmRS512:
		signature, err = signRSA(crypto.SHA512)
	case azkeys.JSONWebKeySignatureAlgorithmES256:
		signature, err = signECDSA()
	case azkeys.JSONWebKeySignatureAlgorithmES384:
		signature, err = signECDSA()
	case azkeys.JSONWebKeySignatureAlgorithmES512:
		signature, err = signECDSA()
	default:
		return azkeys.SignResponse{}, status.Errorf(codes.InvalidArgument, "unsupported signing algorithm: %s", *parameters.Algorithm)
	}
	if err != nil {
		return azkeys.SignResponse{}, status.Errorf(codes.Internal, "unable to sign digest: %v", err)
	}
	return azkeys.SignResponse{KeyOperationResult: azkeys.KeyOperationResult{
		Result: signature,
	}}, nil
}

func toRSAKey(publicKey crypto.PublicKey, kmsKeyID string, keyOperations []*string) *azkeys.JSONWebKey {
	rsaKey := publicKey.(*rsa.PublicKey)
	var s = big.NewInt(int64(rsaKey.E))
	var e = s.Bytes()
	key := &azkeys.JSONWebKey{
		N:      rsaKey.N.Bytes(),
		E:      e,
		KID:    to.Ptr(azkeys.ID(kmsKeyID)),
		KeyOps: keyOperations,
		Kty:    to.Ptr(azkeys.JSONWebKeyTypeRSA),
	}
	return key
}

func toECKey(publicKey crypto.PublicKey, keyName string, curveName azkeys.JSONWebKeyCurveName, keyOperations []*string) *azkeys.JSONWebKey {
	ecdsaKey := publicKey.(*ecdsa.PublicKey)
	key := &azkeys.JSONWebKey{
		Crv: to.Ptr(curveName),
		//D:      ecdsaKey.D.Bytes(),
		KID:    to.Ptr(azkeys.ID(keyName)),
		KeyOps: keyOperations,
		Kty:    to.Ptr(azkeys.JSONWebKeyTypeEC),
		X:      ecdsaKey.X.Bytes(),
		Y:      ecdsaKey.Y.Bytes(),
	}
	return key
}

func (fs *fakeStore) FetchKeyEntry(keyName string) (*fakeKeyEntry, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.fetchKeyEntry(keyName)
}

func (fs *fakeStore) fetchKeyEntry(keyName string) (*fakeKeyEntry, error) {
	keyEntry, ok := fs.fakeKeys[keyName]
	if ok {
		return keyEntry, nil
	}
	return &fakeKeyEntry{}, fmt.Errorf("no such key %q", keyName)
}

func (fs *fakeStore) fetchKeyEntries() []fakeKeyEntry {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	var keyEntries []fakeKeyEntry
	for _, v := range fs.fakeKeys {
		keyEntries = append(keyEntries, *v)
	}
	return keyEntries
}

func getKeyOperations() []*string {
	return []*string{to.Ptr("Sign"), to.Ptr("Verify")}
}
