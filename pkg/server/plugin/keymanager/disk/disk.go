package disk

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/keymanager"
)

type configuration struct {
	Path string `hcl:"path"`
}

type keyEntry struct {
	PrivateKey crypto.PrivateKey
	*keymanager.PublicKey
}

type KeyManager struct {
	mu      sync.RWMutex
	config  *configuration
	entries map[string]*keyEntry
}

func New() *KeyManager {
	return &KeyManager{
		entries: make(map[string]*keyEntry),
	}
}

func (m *KeyManager) GenerateKey(ctx context.Context, req *keymanager.GenerateKeyRequest) (*keymanager.GenerateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, newError("key id is required")
	}
	if req.KeyAlgorithm == keymanager.KeyAlgorithm_UNSPECIFIED_KEY_ALGORITHM {
		return nil, newError("key algorithm is required")
	}

	newEntry, err := generateKeyEntry(req.KeyId, req.KeyAlgorithm)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.config == nil {
		return nil, newError("not configured")
	}

	oldEntry, hasEntry := m.entries[req.KeyId]

	m.entries[req.KeyId] = newEntry

	if err := writeEntries(m.config.Path, entriesSliceFromMap(m.entries)); err != nil {
		delete(m.entries, req.KeyId)
		if hasEntry {
			m.entries[req.KeyId] = oldEntry
		}
		return nil, err
	}

	return &keymanager.GenerateKeyResponse{
		PublicKey: clonePublicKey(newEntry.PublicKey),
	}, nil
}

func (m *KeyManager) GetPublicKey(ctx context.Context, req *keymanager.GetPublicKeyRequest) (*keymanager.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, newError("key id is required")
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

func (m *KeyManager) GetPublicKeys(ctx context.Context, req *keymanager.GetPublicKeysRequest) (*keymanager.GetPublicKeysResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	resp := new(keymanager.GetPublicKeysResponse)
	for _, entry := range entriesSliceFromMap(m.entries) {
		resp.PublicKeys = append(resp.PublicKeys, clonePublicKey(entry.PublicKey))
	}

	return resp, nil
}

func (m *KeyManager) SignData(ctx context.Context, req *keymanager.SignDataRequest) (*keymanager.SignDataResponse, error) {
	if req.KeyId == "" {
		return nil, newError("key id is required")
	}
	if req.HashAlgorithm == keymanager.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM {
		return nil, newError("hash algorithm is required")
	}

	privateKey := m.getPrivateKey(req.KeyId)
	if privateKey == nil {
		return nil, newError("no such key %q", req.KeyId)
	}

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, newError("keypair %q not usable for signing", req.KeyId)
	}

	signature, err := signer.Sign(rand.Reader, req.Data, crypto.Hash(req.HashAlgorithm))
	if err != nil {
		return nil, newError("keypair %q signing operation failed: %v", req.KeyId, err)
	}

	return &keymanager.SignDataResponse{
		Signature: signature,
	}, nil
}

func (m *KeyManager) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	config := new(configuration)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, newError("unable to decode configuration: %v", err)
	}

	if config.Path == "" {
		return nil, newError("path is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.configure(config); err != nil {
		return nil, err
	}

	return &plugin.ConfigureResponse{}, nil
}

func (m *KeyManager) configure(config *configuration) error {
	// only load entry information on first configure
	if m.config == nil {
		entries, err := loadEntries(config.Path)
		if err != nil {
			return err
		}
		m.entries = entriesMapFromSlice(entries)
	}

	m.config = config
	return nil
}

func (m *KeyManager) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}

func (m *KeyManager) getPrivateKey(id string) crypto.PrivateKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if entry := m.entries[id]; entry != nil {
		return entry.PrivateKey
	}
	return nil
}

func generateKeyEntry(keyId string, keyAlgorithm keymanager.KeyAlgorithm) (e *keyEntry, err error) {
	var privateKey crypto.PrivateKey
	var publicKey crypto.PublicKey
	switch keyAlgorithm {
	case keymanager.KeyAlgorithm_ECDSA_P256:
		privateKey, publicKey, err = generateECDSAKey(elliptic.P256())
	case keymanager.KeyAlgorithm_ECDSA_P384:
		privateKey, publicKey, err = generateECDSAKey(elliptic.P384())
	default:
		return nil, newError("unknown key algorithm %q", keyAlgorithm)
	}
	if err != nil {
		return nil, err
	}

	return makeKeyEntry(keyId, keyAlgorithm, privateKey, publicKey)
}

func makeKeyEntry(keyId string, keyAlgorithm keymanager.KeyAlgorithm, privateKey crypto.PrivateKey, publicKey crypto.PublicKey) (*keyEntry, error) {
	pkixData, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, newError("unable to marshal public key: %v", err)
	}

	return &keyEntry{
		PrivateKey: privateKey,
		PublicKey: &keymanager.PublicKey{
			Id:        keyId,
			Algorithm: keyAlgorithm,
			PkixData:  pkixData,
		},
	}, nil
}

func makeKeyEntryFromKey(id string, privateKey crypto.PrivateKey) (*keyEntry, error) {
	switch privateKey := privateKey.(type) {
	case *ecdsa.PrivateKey:
		algorithm, err := ecdsaKeyAlgorithm(privateKey)
		if err != nil {
			return nil, err
		}
		return makeKeyEntry(id, algorithm, privateKey, privateKey.Public())
	default:
		return nil, newError("unexpected private key type %T", privateKey)
	}
}

func generateECDSAKey(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func newError(format string, args ...interface{}) error {
	return fmt.Errorf("keymanager(disk): "+format, args...)
}

// loadEntries loads the entries from a file on disk. If the file does not
// exist then loadEntries returns an empty slice.
func loadEntries(path string) (entries []*keyEntry, err error) {
	blocks, err := pemutil.LoadBlocks(path, pemutil.PrivateKeyType)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	for _, block := range blocks {
		id := block.Headers["Id"]
		if id == "" {
			return nil, newError("PEM block missing Id header")
		}

		entry, err := makeKeyEntryFromKey(id, block.Object)
		if err != nil {
			return nil, err
		}

		entries = append(entries, entry)
	}
	return entries, nil
}

func ecdsaKeyAlgorithm(privateKey *ecdsa.PrivateKey) (keymanager.KeyAlgorithm, error) {
	switch {
	case privateKey.Curve == elliptic.P256():
		return keymanager.KeyAlgorithm_ECDSA_P256, nil
	case privateKey.Curve == elliptic.P384():
		return keymanager.KeyAlgorithm_ECDSA_P384, nil
	default:
		return keymanager.KeyAlgorithm_UNSPECIFIED_KEY_ALGORITHM, newError("no ECDSA algorithm for EC curve: %s",
			privateKey.Curve.Params().Name)
	}
}

func writeEntries(path string, entries []*keyEntry) error {
	var blocks []pemutil.Block
	for _, entry := range entries {
		blocks = append(blocks, pemutil.Block{
			Type: pemutil.PrivateKeyType,
			Headers: map[string]string{
				"Id": entry.Id,
			},
			Object: entry.PrivateKey,
		})
	}

	if err := pemutil.WriteBlocks(path, blocks, 0600); err != nil {
		return newError("unable to write key file: %v", err)
	}

	return nil
}

func entriesSliceFromMap(entriesMap map[string]*keyEntry) (entriesSlice []*keyEntry) {
	// return keys in sorted order for consistency
	ids := make([]string, 0, len(entriesMap))
	for id := range entriesMap {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		entriesSlice = append(entriesSlice, entriesMap[id])
	}
	return entriesSlice
}

func entriesMapFromSlice(entriesSlice []*keyEntry) map[string]*keyEntry {
	entriesMap := make(map[string]*keyEntry, len(entriesSlice))
	for _, entry := range entriesSlice {
		entriesMap[entry.Id] = entry
	}
	return entriesMap
}

func clonePublicKey(publicKey *keymanager.PublicKey) *keymanager.PublicKey {
	return proto.Clone(publicKey).(*keymanager.PublicKey)
}
