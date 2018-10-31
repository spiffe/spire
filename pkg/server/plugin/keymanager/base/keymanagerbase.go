package base

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"sort"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/spiffe/spire/proto/server/keymanager"
)

type KeyEntry struct {
	PrivateKey crypto.PrivateKey
	*keymanager.PublicKey
}

type ErrorFn func(format string, args ...interface{}) error
type WriteFn func(ctx context.Context, entries []*KeyEntry) error

type Impl struct {
	ErrorFn ErrorFn
	WriteFn WriteFn
}

type Base struct {
	impl Impl

	mu      sync.RWMutex
	entries map[string]*KeyEntry
}

func New(impl Impl) *Base {
	return &Base{
		impl:    impl,
		entries: make(map[string]*KeyEntry),
	}
}

func (m *Base) SetEntries(entries []*KeyEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = entriesMapFromSlice(entries)
}

func (m *Base) GenerateKey(ctx context.Context, req *keymanager.GenerateKeyRequest) (*keymanager.GenerateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, m.newError("key id is required")
	}
	if req.KeyType == keymanager.KeyType_UNSPECIFIED_KEY_TYPE {
		return nil, m.newError("key type is required")
	}

	newEntry, err := m.generateKeyEntry(req.KeyId, req.KeyType)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	oldEntry, hasEntry := m.entries[req.KeyId]

	m.entries[req.KeyId] = newEntry

	if m.impl.WriteFn != nil {
		if err := m.impl.WriteFn(ctx, entriesSliceFromMap(m.entries)); err != nil {
			if hasEntry {
				m.entries[req.KeyId] = oldEntry
			} else {
				delete(m.entries, req.KeyId)
			}
			return nil, err
		}
	}

	return &keymanager.GenerateKeyResponse{
		PublicKey: clonePublicKey(newEntry.PublicKey),
	}, nil
}

func (m *Base) GetPublicKey(ctx context.Context, req *keymanager.GetPublicKeyRequest) (*keymanager.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, m.newError("key id is required")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	resp := new(keymanager.GetPublicKeyResponse)
	entry := m.entries[req.KeyId]
	if entry != nil {
		resp.PublicKey = clonePublicKey(entry.PublicKey)
	}

	return resp, nil
}

func (m *Base) GetPublicKeys(ctx context.Context, req *keymanager.GetPublicKeysRequest) (*keymanager.GetPublicKeysResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	resp := new(keymanager.GetPublicKeysResponse)
	for _, entry := range entriesSliceFromMap(m.entries) {
		resp.PublicKeys = append(resp.PublicKeys, clonePublicKey(entry.PublicKey))
	}

	return resp, nil
}

func (m *Base) SignData(ctx context.Context, req *keymanager.SignDataRequest) (*keymanager.SignDataResponse, error) {
	if req.KeyId == "" {
		return nil, m.newError("key id is required")
	}
	if req.SignerOpts == nil {
		return nil, m.newError("signer opts is required")
	}

	var signerOpts crypto.SignerOpts
	switch opts := req.SignerOpts.(type) {
	case *keymanager.SignDataRequest_HashAlgorithm:
		if opts.HashAlgorithm == keymanager.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM {
			return nil, m.newError("hash algorithm is required")
		}
		signerOpts = crypto.Hash(opts.HashAlgorithm)
	case *keymanager.SignDataRequest_PssOptions:
		if opts.PssOptions == nil {
			return nil, m.newError("PSS options are nil")
		}
		if opts.PssOptions.HashAlgorithm == keymanager.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM {
			return nil, m.newError("hash algorithm is required")
		}
		signerOpts = &rsa.PSSOptions{
			SaltLength: int(opts.PssOptions.SaltLength),
			Hash:       crypto.Hash(opts.PssOptions.HashAlgorithm),
		}
	default:
		return nil, m.newError("unsupported signer opts type %T", opts)
	}

	privateKey := m.getPrivateKey(req.KeyId)
	if privateKey == nil {
		return nil, m.newError("no such key %q", req.KeyId)
	}

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, m.newError("keypair %q not usable for signing", req.KeyId)
	}

	signature, err := signer.Sign(rand.Reader, req.Data, signerOpts)
	if err != nil {
		return nil, m.newError("keypair %q signing operation failed: %v", req.KeyId, err)
	}

	return &keymanager.SignDataResponse{
		Signature: signature,
	}, nil
}

func (m *Base) getPrivateKey(id string) crypto.PrivateKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if entry := m.entries[id]; entry != nil {
		return entry.PrivateKey
	}
	return nil
}

func (m *Base) generateKeyEntry(keyId string, keyType keymanager.KeyType) (e *KeyEntry, err error) {
	var privateKey crypto.PrivateKey
	var publicKey crypto.PublicKey
	switch keyType {
	case keymanager.KeyType_EC_P256:
		privateKey, publicKey, err = generateECKey(elliptic.P256())
	case keymanager.KeyType_EC_P384:
		privateKey, publicKey, err = generateECKey(elliptic.P384())
	case keymanager.KeyType_RSA_1024:
		privateKey, publicKey, err = generateRSAKey(1024)
	case keymanager.KeyType_RSA_2048:
		privateKey, publicKey, err = generateRSAKey(2048)
	case keymanager.KeyType_RSA_4096:
		privateKey, publicKey, err = generateRSAKey(4096)
	default:
		return nil, m.newError("unknown key type %q", keyType)
	}
	if err != nil {
		return nil, err
	}

	entry, err := makeKeyEntry(keyId, keyType, privateKey, publicKey)
	if err != nil {
		return nil, m.newError("unable to make key entry: %v", err)
	}

	return entry, nil
}

func (m *Base) newError(format string, args ...interface{}) error {
	return m.impl.ErrorFn(format, args...)
}

func makeKeyEntry(keyId string, keyType keymanager.KeyType, privateKey crypto.PrivateKey, publicKey crypto.PublicKey) (*KeyEntry, error) {
	pkixData, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return &KeyEntry{
		PrivateKey: privateKey,
		PublicKey: &keymanager.PublicKey{
			Id:       keyId,
			Type:     keyType,
			PkixData: pkixData,
		},
	}, nil
}

func MakeKeyEntryFromKey(id string, privateKey crypto.PrivateKey) (*KeyEntry, error) {
	switch privateKey := privateKey.(type) {
	case *ecdsa.PrivateKey:
		keyType, err := ecdsaKeyType(privateKey)
		if err != nil {
			return nil, err
		}
		return makeKeyEntry(id, keyType, privateKey, privateKey.Public())
	case *rsa.PrivateKey:
		keyType, err := rsaKeyType(privateKey)
		if err != nil {
			return nil, err
		}
		return makeKeyEntry(id, keyType, privateKey, privateKey.Public())
	default:
		return nil, fmt.Errorf("unexpected private key type %T", privateKey)
	}
}

func rsaKeyType(privateKey *rsa.PrivateKey) (keymanager.KeyType, error) {
	bits := privateKey.N.BitLen()
	switch bits {
	case 1024:
		return keymanager.KeyType_RSA_1024, nil
	case 2048:
		return keymanager.KeyType_RSA_2048, nil
	case 4096:
		return keymanager.KeyType_RSA_4096, nil
	default:
		return keymanager.KeyType_UNSPECIFIED_KEY_TYPE, fmt.Errorf("no RSA key type for key bit length: %d", bits)
	}
}

func ecdsaKeyType(privateKey *ecdsa.PrivateKey) (keymanager.KeyType, error) {
	switch {
	case privateKey.Curve == elliptic.P256():
		return keymanager.KeyType_EC_P256, nil
	case privateKey.Curve == elliptic.P384():
		return keymanager.KeyType_EC_P384, nil
	default:
		return keymanager.KeyType_UNSPECIFIED_KEY_TYPE, fmt.Errorf("no EC key type for EC curve: %s",
			privateKey.Curve.Params().Name)
	}
}

func generateRSAKey(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func generateECKey(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func entriesSliceFromMap(entriesMap map[string]*KeyEntry) (entriesSlice []*KeyEntry) {
	for _, entry := range entriesMap {
		entriesSlice = append(entriesSlice, entry)
	}
	SortKeyEntries(entriesSlice)
	return entriesSlice
}

func entriesMapFromSlice(entriesSlice []*KeyEntry) map[string]*KeyEntry {
	// return keys in sorted order for consistency
	entriesMap := make(map[string]*KeyEntry, len(entriesSlice))
	for _, entry := range entriesSlice {
		entriesMap[entry.Id] = entry
	}
	return entriesMap
}

func clonePublicKey(publicKey *keymanager.PublicKey) *keymanager.PublicKey {
	return proto.Clone(publicKey).(*keymanager.PublicKey)
}

func SortKeyEntries(entries []*KeyEntry) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Id < entries[j].Id
	})
}
