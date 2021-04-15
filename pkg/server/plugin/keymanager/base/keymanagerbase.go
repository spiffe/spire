package keymanagerbase

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

	keymanagerv0 "github.com/spiffe/spire/proto/spire/plugin/server/keymanager/v0"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// KeyEntry is an entry maintained by the key manager
type KeyEntry struct {
	PrivateKey crypto.Signer
	*keymanagerv0.PublicKey
}

// Funcs is a collection of optional callbacks. Default implementations will be
// used when not provided.
type Funcs struct {
	WriteEntries       func(ctx context.Context, entries []*KeyEntry) error
	GenerateRSA1024Key func() (*rsa.PrivateKey, error)
	GenerateRSA2048Key func() (*rsa.PrivateKey, error)
	GenerateRSA4096Key func() (*rsa.PrivateKey, error)
	GenerateEC256Key   func() (*ecdsa.PrivateKey, error)
	GenerateEC384Key   func() (*ecdsa.PrivateKey, error)
}

// Base is the base keymanager implementation
type Base struct {
	keymanagerv0.UnsafeKeyManagerServer
	funcs Funcs

	mu      sync.RWMutex
	entries map[string]*KeyEntry
}

// New creates a new base key manager using the provided Funcs. Default
// implementations are provided for any that aren't set.
func New(funcs Funcs) *Base {
	if funcs.GenerateRSA1024Key == nil {
		funcs.GenerateRSA1024Key = generateRSA1024Key
	}
	if funcs.GenerateRSA2048Key == nil {
		funcs.GenerateRSA2048Key = generateRSA2048Key
	}
	if funcs.GenerateRSA4096Key == nil {
		funcs.GenerateRSA4096Key = generateRSA4096Key
	}
	if funcs.GenerateEC256Key == nil {
		funcs.GenerateEC256Key = generateEC256Key
	}
	if funcs.GenerateEC384Key == nil {
		funcs.GenerateEC384Key = generateEC384Key
	}
	return &Base{
		funcs:   funcs,
		entries: make(map[string]*KeyEntry),
	}
}

// SetEntries is used to replace the set of managed entries. This is generally
// called by implementations when they are first loaded to set the initial set
// of entries.
func (m *Base) SetEntries(entries []*KeyEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = entriesMapFromSlice(entries)
}

// GenerateKey implements the KeyManager RPC of the same name.
func (m *Base) GenerateKey(ctx context.Context, req *keymanagerv0.GenerateKeyRequest) (*keymanagerv0.GenerateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.KeyType == keymanagerv0.KeyType_UNSPECIFIED_KEY_TYPE {
		return nil, status.Error(codes.InvalidArgument, "key type is required")
	}

	newEntry, err := m.generateKeyEntry(req.KeyId, req.KeyType)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	oldEntry, hasEntry := m.entries[req.KeyId]

	m.entries[req.KeyId] = newEntry

	if m.funcs.WriteEntries != nil {
		if err := m.funcs.WriteEntries(ctx, entriesSliceFromMap(m.entries)); err != nil {
			if hasEntry {
				m.entries[req.KeyId] = oldEntry
			} else {
				delete(m.entries, req.KeyId)
			}
			return nil, err
		}
	}

	return &keymanagerv0.GenerateKeyResponse{
		PublicKey: clonePublicKey(newEntry.PublicKey),
	}, nil
}

// GetPublicKey implements the KeyManager RPC of the same name.
func (m *Base) GetPublicKey(ctx context.Context, req *keymanagerv0.GetPublicKeyRequest) (*keymanagerv0.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	resp := new(keymanagerv0.GetPublicKeyResponse)
	entry := m.entries[req.KeyId]
	if entry != nil {
		resp.PublicKey = clonePublicKey(entry.PublicKey)
	}

	return resp, nil
}

// GetPublicKeys implements the KeyManager RPC of the same name.
func (m *Base) GetPublicKeys(ctx context.Context, req *keymanagerv0.GetPublicKeysRequest) (*keymanagerv0.GetPublicKeysResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	resp := new(keymanagerv0.GetPublicKeysResponse)
	for _, entry := range entriesSliceFromMap(m.entries) {
		resp.PublicKeys = append(resp.PublicKeys, clonePublicKey(entry.PublicKey))
	}

	return resp, nil
}

// SignData implements the KeyManager RPC of the same name.
func (m *Base) SignData(ctx context.Context, req *keymanagerv0.SignDataRequest) (*keymanagerv0.SignDataResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.SignerOpts == nil {
		return nil, status.Error(codes.InvalidArgument, "signer opts is required")
	}

	var signerOpts crypto.SignerOpts
	switch opts := req.SignerOpts.(type) {
	case *keymanagerv0.SignDataRequest_HashAlgorithm:
		if opts.HashAlgorithm == keymanagerv0.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM {
			return nil, status.Error(codes.InvalidArgument, "hash algorithm is required")
		}
		signerOpts = crypto.Hash(opts.HashAlgorithm)
	case *keymanagerv0.SignDataRequest_PssOptions:
		if opts.PssOptions == nil {
			return nil, status.Error(codes.InvalidArgument, "PSS options are nil")
		}
		if opts.PssOptions.HashAlgorithm == keymanagerv0.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM {
			return nil, status.Error(codes.InvalidArgument, "hash algorithm is required")
		}
		signerOpts = &rsa.PSSOptions{
			SaltLength: int(opts.PssOptions.SaltLength),
			Hash:       crypto.Hash(opts.PssOptions.HashAlgorithm),
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported signer opts type %T", opts)
	}

	privateKey := m.getPrivateKey(req.KeyId)
	if privateKey == nil {
		return nil, status.Errorf(codes.NotFound, "no such key %q", req.KeyId)
	}

	signature, err := privateKey.Sign(rand.Reader, req.Data, signerOpts)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "keypair %q signing operation failed: %v", req.KeyId, err)
	}

	return &keymanagerv0.SignDataResponse{
		Signature: signature,
	}, nil
}

func (m *Base) getPrivateKey(id string) crypto.Signer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if entry := m.entries[id]; entry != nil {
		return entry.PrivateKey
	}
	return nil
}

func (m *Base) generateKeyEntry(keyID string, keyType keymanagerv0.KeyType) (e *KeyEntry, err error) {
	var privateKey crypto.Signer
	switch keyType {
	case keymanagerv0.KeyType_EC_P256:
		privateKey, err = m.funcs.GenerateEC256Key()
	case keymanagerv0.KeyType_EC_P384:
		privateKey, err = m.funcs.GenerateEC384Key()
	case keymanagerv0.KeyType_RSA_1024:
		privateKey, err = m.funcs.GenerateRSA1024Key()
	case keymanagerv0.KeyType_RSA_2048:
		privateKey, err = m.funcs.GenerateRSA2048Key()
	case keymanagerv0.KeyType_RSA_4096:
		privateKey, err = m.funcs.GenerateRSA4096Key()
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown key type %q", keyType)
	}
	if err != nil {
		return nil, err
	}

	entry, err := makeKeyEntry(keyID, keyType, privateKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to make key entry: %v", err)
	}

	return entry, nil
}

func makeKeyEntry(keyID string, keyType keymanagerv0.KeyType, privateKey crypto.Signer) (*KeyEntry, error) {
	pkixData, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, err
	}

	return &KeyEntry{
		PrivateKey: privateKey,
		PublicKey: &keymanagerv0.PublicKey{
			Id:       keyID,
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
		return makeKeyEntry(id, keyType, privateKey)
	case *rsa.PrivateKey:
		keyType, err := rsaKeyType(privateKey)
		if err != nil {
			return nil, err
		}
		return makeKeyEntry(id, keyType, privateKey)
	default:
		return nil, fmt.Errorf("unexpected private key type %T", privateKey)
	}
}

func rsaKeyType(privateKey *rsa.PrivateKey) (keymanagerv0.KeyType, error) {
	bits := privateKey.N.BitLen()
	switch bits {
	case 1024:
		return keymanagerv0.KeyType_RSA_1024, nil
	case 2048:
		return keymanagerv0.KeyType_RSA_2048, nil
	case 4096:
		return keymanagerv0.KeyType_RSA_4096, nil
	default:
		return keymanagerv0.KeyType_UNSPECIFIED_KEY_TYPE, fmt.Errorf("no RSA key type for key bit length: %d", bits)
	}
}

func ecdsaKeyType(privateKey *ecdsa.PrivateKey) (keymanagerv0.KeyType, error) {
	switch {
	case privateKey.Curve == elliptic.P256():
		return keymanagerv0.KeyType_EC_P256, nil
	case privateKey.Curve == elliptic.P384():
		return keymanagerv0.KeyType_EC_P384, nil
	default:
		return keymanagerv0.KeyType_UNSPECIFIED_KEY_TYPE, fmt.Errorf("no EC key type for EC curve: %s",
			privateKey.Curve.Params().Name)
	}
}

func generateRSA1024Key() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 1024) //nolint: gosec
}

func generateRSA2048Key() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func generateRSA4096Key() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 4096)
}

func generateEC256Key() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func generateEC384Key() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
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

func clonePublicKey(publicKey *keymanagerv0.PublicKey) *keymanagerv0.PublicKey {
	return proto.Clone(publicKey).(*keymanagerv0.PublicKey)
}

func SortKeyEntries(entries []*KeyEntry) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Id < entries[j].Id
	})
}
