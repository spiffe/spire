package keymanagerbase

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"

	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"github.com/spiffe/spire/pkg/common/util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// KeyEntry is an entry maintained by the key manager
type KeyEntry struct {
	PrivateKey crypto.Signer
	*keymanagerv1.PublicKey
}

// Config is a collection of optional callbacks. Default implementations will be
// used when not provided.
type Config struct {
	// Generator is an optional key generator.
	Generator Generator

	// WriteEntries is an optional callback used to persist key entries
	WriteEntries func(ctx context.Context, entries []*KeyEntry) error
}

// Generator is a key generator
type Generator interface {
	GenerateRSA2048Key() (crypto.Signer, error)
	GenerateRSA4096Key() (crypto.Signer, error)
	GenerateEC256Key() (crypto.Signer, error)
	GenerateEC384Key() (crypto.Signer, error)
}

// Base is the base KeyManager implementation
type Base struct {
	keymanagerv1.UnsafeKeyManagerServer
	config Config

	mu      sync.RWMutex
	entries map[string]*KeyEntry
}

// New creates a new base key manager using the provided config.
func New(config Config) *Base {
	if config.Generator == nil {
		config.Generator = defaultGenerator{}
	}
	return &Base{
		config:  config,
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
	// populate the fingerprints
	for _, entry := range m.entries {
		entry.PublicKey.Fingerprint = makeFingerprint(entry.PublicKey.PkixData)
	}
}

// GenerateKey implements the KeyManager RPC of the same name.
func (m *Base) GenerateKey(ctx context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	resp, err := m.generateKey(ctx, req)
	return resp, prefixStatus(err, "failed to generate key")
}

// GetPublicKey implements the KeyManager RPC of the same name.
func (m *Base) GetPublicKey(_ context.Context, req *keymanagerv1.GetPublicKeyRequest) (*keymanagerv1.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	resp := new(keymanagerv1.GetPublicKeyResponse)
	entry := m.entries[req.KeyId]
	if entry != nil {
		resp.PublicKey = clonePublicKey(entry.PublicKey)
	}

	return resp, nil
}

// GetPublicKeys implements the KeyManager RPC of the same name.
func (m *Base) GetPublicKeys(context.Context, *keymanagerv1.GetPublicKeysRequest) (*keymanagerv1.GetPublicKeysResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	resp := new(keymanagerv1.GetPublicKeysResponse)
	for _, entry := range entriesSliceFromMap(m.entries) {
		resp.PublicKeys = append(resp.PublicKeys, clonePublicKey(entry.PublicKey))
	}

	return resp, nil
}

// SignData implements the KeyManager RPC of the same name.
func (m *Base) SignData(_ context.Context, req *keymanagerv1.SignDataRequest) (*keymanagerv1.SignDataResponse, error) {
	resp, err := m.signData(req)
	return resp, prefixStatus(err, "failed to sign data")
}

func (m *Base) generateKey(ctx context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.KeyType == keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE {
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

	if m.config.WriteEntries != nil {
		if err := m.config.WriteEntries(ctx, entriesSliceFromMap(m.entries)); err != nil {
			if hasEntry {
				m.entries[req.KeyId] = oldEntry
			} else {
				delete(m.entries, req.KeyId)
			}
			return nil, err
		}
	}

	return &keymanagerv1.GenerateKeyResponse{
		PublicKey: clonePublicKey(newEntry.PublicKey),
	}, nil
}

func (m *Base) signData(req *keymanagerv1.SignDataRequest) (*keymanagerv1.SignDataResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.SignerOpts == nil {
		return nil, status.Error(codes.InvalidArgument, "signer opts is required")
	}

	var signerOpts crypto.SignerOpts
	switch opts := req.SignerOpts.(type) {
	case *keymanagerv1.SignDataRequest_HashAlgorithm:
		if opts.HashAlgorithm == keymanagerv1.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM {
			return nil, status.Error(codes.InvalidArgument, "hash algorithm is required")
		}
		signerOpts = util.MustCast[crypto.Hash](opts.HashAlgorithm)
	case *keymanagerv1.SignDataRequest_PssOptions:
		if opts.PssOptions == nil {
			return nil, status.Error(codes.InvalidArgument, "PSS options are nil")
		}
		if opts.PssOptions.HashAlgorithm == keymanagerv1.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM {
			return nil, status.Error(codes.InvalidArgument, "hash algorithm in PSS options is required")
		}
		signerOpts = &rsa.PSSOptions{
			SaltLength: int(opts.PssOptions.SaltLength),
			Hash:       util.MustCast[crypto.Hash](opts.PssOptions.HashAlgorithm),
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported signer opts type %T", opts)
	}

	privateKey, fingerprint, ok := m.getPrivateKeyAndFingerprint(req.KeyId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no such key %q", req.KeyId)
	}

	signature, err := privateKey.Sign(rand.Reader, req.Data, signerOpts)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "keypair %q signing operation failed: %v", req.KeyId, err)
	}

	return &keymanagerv1.SignDataResponse{
		Signature:      signature,
		KeyFingerprint: fingerprint,
	}, nil
}

func (m *Base) getPrivateKeyAndFingerprint(id string) (crypto.Signer, string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if entry := m.entries[id]; entry != nil {
		return entry.PrivateKey, entry.PublicKey.Fingerprint, true
	}
	return nil, "", false
}

func (m *Base) generateKeyEntry(keyID string, keyType keymanagerv1.KeyType) (e *KeyEntry, err error) {
	var privateKey crypto.Signer
	switch keyType {
	case keymanagerv1.KeyType_EC_P256:
		privateKey, err = m.config.Generator.GenerateEC256Key()
	case keymanagerv1.KeyType_EC_P384:
		privateKey, err = m.config.Generator.GenerateEC384Key()
	case keymanagerv1.KeyType_RSA_2048:
		privateKey, err = m.config.Generator.GenerateRSA2048Key()
	case keymanagerv1.KeyType_RSA_4096:
		privateKey, err = m.config.Generator.GenerateRSA4096Key()
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unable to generate key %q for unknown key type %q", keyID, keyType)
	}
	if err != nil {
		return nil, err
	}

	entry, err := makeKeyEntry(keyID, keyType, privateKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to make key entry for new key %q: %v", keyID, err)
	}

	return entry, nil
}

func makeKeyEntry(keyID string, keyType keymanagerv1.KeyType, privateKey crypto.Signer) (*KeyEntry, error) {
	pkixData, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key for entry %q: %w", keyID, err)
	}

	return &KeyEntry{
		PrivateKey: privateKey,
		PublicKey: &keymanagerv1.PublicKey{
			Id:          keyID,
			Type:        keyType,
			PkixData:    pkixData,
			Fingerprint: makeFingerprint(pkixData),
		},
	}, nil
}

func MakeKeyEntryFromKey(id string, privateKey crypto.PrivateKey) (*KeyEntry, error) {
	switch privateKey := privateKey.(type) {
	case *ecdsa.PrivateKey:
		keyType, err := ecdsaKeyType(privateKey)
		if err != nil {
			return nil, fmt.Errorf("unable to make key entry for key %q: %w", id, err)
		}
		return makeKeyEntry(id, keyType, privateKey)
	case *rsa.PrivateKey:
		keyType, err := rsaKeyType(privateKey)
		if err != nil {
			return nil, fmt.Errorf("unable to make key entry for key %q: %w", id, err)
		}
		return makeKeyEntry(id, keyType, privateKey)
	default:
		return nil, fmt.Errorf("unexpected private key type %T for key %q", privateKey, id)
	}
}

func rsaKeyType(privateKey *rsa.PrivateKey) (keymanagerv1.KeyType, error) {
	bits := privateKey.N.BitLen()
	switch bits {
	case 2048:
		return keymanagerv1.KeyType_RSA_2048, nil
	case 4096:
		return keymanagerv1.KeyType_RSA_4096, nil
	default:
		return keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE, fmt.Errorf("no RSA key type for key bit length: %d", bits)
	}
}

func ecdsaKeyType(privateKey *ecdsa.PrivateKey) (keymanagerv1.KeyType, error) {
	switch {
	case privateKey.Curve == elliptic.P256():
		return keymanagerv1.KeyType_EC_P256, nil
	case privateKey.Curve == elliptic.P384():
		return keymanagerv1.KeyType_EC_P384, nil
	default:
		return keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE, fmt.Errorf("no EC key type for EC curve: %s",
			privateKey.Curve.Params().Name)
	}
}

type defaultGenerator struct{}

func (defaultGenerator) GenerateRSA2048Key() (crypto.Signer, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func (defaultGenerator) GenerateRSA4096Key() (crypto.Signer, error) {
	return rsa.GenerateKey(rand.Reader, 4096)
}

func (defaultGenerator) GenerateEC256Key() (crypto.Signer, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func (defaultGenerator) GenerateEC384Key() (crypto.Signer, error) {
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

func clonePublicKey(publicKey *keymanagerv1.PublicKey) *keymanagerv1.PublicKey {
	return proto.Clone(publicKey).(*keymanagerv1.PublicKey)
}

func makeFingerprint(pkixData []byte) string {
	s := sha256.Sum256(pkixData)
	return hex.EncodeToString(s[:])
}

func SortKeyEntries(entries []*KeyEntry) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Id < entries[j].Id
	})
}

func prefixStatus(err error, prefix string) error {
	st := status.Convert(err)
	if st.Code() != codes.OK {
		return status.Error(st.Code(), prefix+": "+st.Message())
	}
	return err
}
