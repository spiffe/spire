package disk

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"text/template"
	"time"

	sprig "github.com/Masterminds/sprig/v3"
	"github.com/gofrs/uuid/v5"
	"github.com/hashicorp/hcl"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	keymanagerbase "github.com/spiffe/spire/pkg/server/plugin/keymanager/base"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Generator = keymanagerbase.Generator

func BuiltIn() catalog.BuiltIn {
	return asBuiltIn(newKeyManager(nil))
}

func TestBuiltIn(generator Generator) catalog.BuiltIn {
	return asBuiltIn(newKeyManager(generator))
}

func asBuiltIn(p *KeyManager) catalog.BuiltIn {
	return catalog.MakeBuiltIn("disk",
		keymanagerv1.KeyManagerPluginServer(p),
		configv1.ConfigServiceServer(p))
}

type configuration struct {
	KeysPath           string            `hcl:"keys_path"`
	KeyIdentifierFile  string            `hcl:"key_identifier_file"`
	KeyIdentifierValue string            `hcl:"key_identifier_value"`
	SharedKeys         *SharedKeysConfig `hcl:"shared_keys"`
}

type SharedKeysConfig struct {
	CryptoKeyTemplate string `hcl:"crypto_key_template"`
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *configuration {
	newConfig := new(configuration)
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	if newConfig.KeysPath == "" {
		status.ReportError("keys_path is required")
	}

	if newConfig.SharedKeys != nil {
		if newConfig.SharedKeys.CryptoKeyTemplate == "" {
			status.ReportError("crypto_key_template is required when shared_keys is enabled")
		}
		if newConfig.KeyIdentifierFile == "" && newConfig.KeyIdentifierValue == "" {
			status.ReportError("key_identifier_file or key_identifier_value is required when shared_keys is enabled")
		}
	}

	return newConfig
}

type KeyManager struct {
	*keymanagerbase.Base
	configv1.UnimplementedConfigServer

	mu       sync.Mutex
	config   *configuration
	metadata map[string]time.Time

	generator   Generator
	tpl         *template.Template
	trustDomain string
	serverID    string
}

func newKeyManager(generator Generator) *KeyManager {
	if generator == nil {
		generator = keymanagerbase.DefaultGenerator()
	}
	m := &KeyManager{
		generator: generator,
	}
	m.Base = keymanagerbase.New(keymanagerbase.Config{
		Generator: generator,
	})
	return m
}

func (m *KeyManager) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.configure(newConfig, req.CoreConfiguration.TrustDomain); err != nil {
		return nil, err
	}

	return &configv1.ConfigureResponse{}, nil
}

func (m *KeyManager) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

func (m *KeyManager) configure(config *configuration, trustDomain string) error {
	serverID := config.KeyIdentifierValue
	if serverID == "" && config.KeyIdentifierFile != "" {
		var err error
		serverID, err = getOrCreateServerID(config.KeyIdentifierFile)
		if err != nil {
			return err
		}
	}

	var tpl *template.Template
	if config.SharedKeys != nil {
		var err error
		tpl, err = template.New("crypto_key_template").Funcs(sprig.TxtFuncMap()).Parse(config.SharedKeys.CryptoKeyTemplate)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "failed to parse crypto_key_template: %v", err)
		}
		if err := validateTemplateVariesWithKeyID(tpl); err != nil {
			return status.Errorf(codes.InvalidArgument, "crypto_key_template: %v", err)
		}
	}

	// only load entry information on first configure
	if m.config == nil {
		entries, metadata, err := loadEntries(config.KeysPath, serverID, config.SharedKeys != nil)
		if err != nil {
			return err
		}
		m.Base.SetEntries(entries)
		m.metadata = metadata
		m.trustDomain = trustDomain
	}

	m.tpl = tpl
	m.serverID = serverID
	m.config = config
	return nil
}

func (m *KeyManager) GenerateKey(ctx context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.KeyType == keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE {
		return nil, status.Error(codes.InvalidArgument, "key type is required")
	}

	m.mu.Lock()
	config := m.config
	m.mu.Unlock()

	if config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}

	// checkReuse returns the existing key entry if it can be reused: same logical ID,
	// matching key type, and (in shared-keys mode) created within the freshness window.
	checkReuse := func(entries []*keymanagerbase.KeyEntry, metadata map[string]time.Time) *keymanagerbase.KeyEntry {
		var candidate *keymanagerbase.KeyEntry
		for _, e := range entries {
			if e.Id == req.KeyId {
				candidate = e
				break
			}
		}
		if candidate == nil {
			return nil
		}

		// Reject type-mismatched entries to avoid returning, e.g., an RSA key when EC is requested.
		if storedType, ok := keyTypeFromSigner(candidate.PrivateKey); !ok || storedType != req.KeyType {
			return nil
		}

		// Only JWT signing keys are shared across servers. X509 CA and WIT keys
		// remain per-server, so they are never reused from the shared store.
		if config.SharedKeys != nil && keymanager.IsSharedKeyID(req.KeyId) {
			createdAt, ok := metadata[req.KeyId]
			if ok && time.Since(createdAt) < 15*time.Minute {
				return candidate
			}
			return nil
		}

		return nil
	}

	lock := newFileLock(config.KeysPath + ".lock")

	// Phase 1: Optimistic Check
	candidate, err := func() (*keymanagerbase.KeyEntry, error) {
		if err := lock.Lock(); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to acquire lock: %v", err)
		}
		defer func() { _ = lock.Unlock() }()

		entries, metadata, err := loadEntries(config.KeysPath, m.serverID, config.SharedKeys != nil)
		if err != nil {
			return nil, err
		}

		// Update memory
		m.Base.SetEntries(entries)
		m.mu.Lock()
		m.metadata = metadata

		m.mu.Unlock()

		return checkReuse(entries, metadata), nil
	}()

	if err != nil {
		return nil, err
	}
	if candidate != nil {
		return &keymanagerv1.GenerateKeyResponse{
			PublicKey: candidate.PublicKey,
		}, nil
	}

	// Phase 2: Generate
	var newKey crypto.Signer
	switch req.KeyType {
	case keymanagerv1.KeyType_EC_P256:
		newKey, err = m.generator.GenerateEC256Key()
	case keymanagerv1.KeyType_EC_P384:
		newKey, err = m.generator.GenerateEC384Key()
	case keymanagerv1.KeyType_RSA_2048:
		newKey, err = m.generator.GenerateRSA2048Key()
	case keymanagerv1.KeyType_RSA_4096:
		newKey, err = m.generator.GenerateRSA4096Key()
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unable to generate key %q for unknown key type %q", req.KeyId, req.KeyType)
	}
	if err != nil {
		return nil, err
	}

	newEntry, err := keymanagerbase.MakeKeyEntryFromKey(req.KeyId, newKey)
	if err != nil {
		return nil, err
	}

	// Phase 3: Persist
	if err := lock.Lock(); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to acquire lock: %v", err)
	}
	defer func() { _ = lock.Unlock() }()

	// Reload again
	entries, metadata, err := loadEntries(config.KeysPath, m.serverID, config.SharedKeys != nil)
	if err != nil {
		return nil, err
	}
	m.Base.SetEntries(entries)
	m.mu.Lock()
	m.metadata = metadata
	m.mu.Unlock()

	// Double check reuse
	if candidate := checkReuse(entries, metadata); candidate != nil {
		return &keymanagerv1.GenerateKeyResponse{
			PublicKey: candidate.PublicKey,
		}, nil
	}

	// Persist the new key, preserving keys owned by other servers that share
	// the same file.
	if err := m.persistKey(config, req.KeyId, newKey, time.Now()); err != nil {
		return nil, err
	}

	// Update memory with this server's view of the file.
	entries, metadata, err = loadEntries(config.KeysPath, m.serverID, config.SharedKeys != nil)
	if err != nil {
		return nil, err
	}
	m.Base.SetEntries(entries)
	m.mu.Lock()
	m.metadata = metadata
	m.mu.Unlock()

	return &keymanagerv1.GenerateKeyResponse{
		PublicKey: newEntry.PublicKey,
	}, nil
}

type entriesData struct {
	// Keys is a map of key ID to the key entry.
	// The value can be either base64 encoded PKCS8 bytes (legacy) or a keyEntryRecord.
	Keys map[string]json.RawMessage `json:"keys"`
}

type keyEntryRecord struct {
	Id         string    `json:"id"`
	PrivateKey []byte    `json:"private_key"` // #nosec G101
	CreatedAt  time.Time `json:"created_at"`
	ServerID   string    `json:"server_id,omitempty"`
}

func loadKeyData(path string) (*entriesData, error) {
	data := &entriesData{Keys: make(map[string]json.RawMessage)}
	jsonBytes, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return data, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(jsonBytes, data); err != nil {
		return nil, status.Errorf(codes.Internal, "unable to decode keys JSON: %v", err)
	}
	if data.Keys == nil {
		data.Keys = make(map[string]json.RawMessage)
	}
	return data, nil
}

func writeKeyData(path string, data *entriesData) error {
	jsonBytes, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal entries: %v", err)
	}
	if err := diskutil.AtomicWritePrivateFile(path, jsonBytes); err != nil {
		return status.Errorf(codes.Internal, "unable to write entries: %v", err)
	}
	return nil
}

// decodeRecord parses a stored key, supporting both the keyEntryRecord JSON format
// and the legacy base64-encoded PKCS8 string format.
func decodeRecord(storageID string, raw json.RawMessage) (logicalID string, keyBytes []byte, serverID string, createdAt time.Time, err error) {
	// Detect format: JSON objects start with '{', legacy base64-encoded PKCS8 starts with '"'.
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var record keyEntryRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			return "", nil, "", time.Time{}, status.Errorf(codes.Internal, "unable to decode key %q: %v", storageID, err)
		}
		if record.PrivateKey == nil {
			return "", nil, "", time.Time{}, status.Errorf(codes.Internal, "missing private key for key %q", storageID)
		}
		if record.Id == "" {
			return "", nil, "", time.Time{}, status.Errorf(codes.Internal, "missing key id for key %q", storageID)
		}
		return record.Id, record.PrivateKey, record.ServerID, record.CreatedAt, nil
	}

	// Legacy format: the map value is a JSON string containing base64-encoded PKCS8 bytes.
	if err := json.Unmarshal(raw, &keyBytes); err != nil {
		return "", nil, "", time.Time{}, status.Errorf(codes.Internal, "unable to decode legacy key %q: %v", storageID, err)
	}
	return storageID, keyBytes, "", time.Time{}, nil
}

// loadEntries loads the key entries managed by this server. In shared mode the
// keys file may contain keys owned by other servers; only the shared (JWT)
// signing keys and this server's own keys are surfaced, so that GetKeys and the
// CA journal lookup do not see another server's X509 CA or WIT keys.
func loadEntries(path, serverID string, shared bool) ([]*keymanagerbase.KeyEntry, map[string]time.Time, error) {
	data, err := loadKeyData(path)
	if err != nil {
		return nil, nil, err
	}

	var entries []*keymanagerbase.KeyEntry
	metadata := make(map[string]time.Time)

	for storageID, raw := range data.Keys {
		logicalID, keyBytes, ownerServerID, createdAt, err := decodeRecord(storageID, raw)
		if err != nil {
			return nil, nil, err
		}

		if shared && !keymanager.IsSharedKeyID(logicalID) && ownerServerID != serverID {
			continue
		}

		key, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, nil, status.Errorf(codes.Internal, "unable to parse key %q: %v", storageID, err)
		}
		entry, err := keymanagerbase.MakeKeyEntryFromKey(logicalID, key)
		if err != nil {
			return nil, nil, status.Errorf(codes.Internal, "unable to make entry %q: %v", storageID, err)
		}
		entries = append(entries, entry)
		if !createdAt.IsZero() {
			metadata[logicalID] = createdAt
		}
	}
	return entries, metadata, nil
}

// storageIDFor computes the map key under which a key is stored in the keys file.
// Shared (JWT) keys use the configured template so that all servers agree on the
// same slot; other key types are namespaced per server so they remain isolated.
func (m *KeyManager) storageIDFor(keyID string) (string, error) {
	if m.tpl == nil {
		return keyID, nil
	}
	if keymanager.IsSharedKeyID(keyID) {
		var buf bytes.Buffer
		if err := m.tpl.Execute(&buf, struct {
			TrustDomain string
			KeyID       string
		}{TrustDomain: m.trustDomain, KeyID: keyID}); err != nil {
			return "", status.Errorf(codes.Internal, "unable to calculate storage ID: %v", err)
		}
		return buf.String(), nil
	}
	return m.serverID + "/" + keyID, nil
}

// persistKey stores a single key in the keys file, preserving any keys owned by
// other servers that share the same file.
func (m *KeyManager) persistKey(config *configuration, keyID string, key crypto.Signer, createdAt time.Time) error {
	data, err := loadKeyData(config.KeysPath)
	if err != nil {
		return err
	}

	storageID, err := m.storageIDFor(keyID)
	if err != nil {
		return err
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	record := keyEntryRecord{
		Id:         keyID,
		PrivateKey: keyBytes,
		CreatedAt:  createdAt,
	}
	if config.SharedKeys != nil && !keymanager.IsSharedKeyID(keyID) {
		record.ServerID = m.serverID
	}

	recordBytes, err := json.Marshal(record)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal key entry %q: %v", keyID, err)
	}
	data.Keys[storageID] = recordBytes

	return writeKeyData(config.KeysPath, data)
}

func getOrCreateServerID(idPath string) (string, error) {
	data, err := os.ReadFile(idPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return createServerID(idPath)
	case err != nil:
		return "", status.Errorf(codes.Internal, "failed to read server id from path: %v", err)
	}

	serverID, err := uuid.FromString(string(data))
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to parse server id from path: %v", err)
	}
	return serverID.String(), nil
}

func createServerID(idPath string) (string, error) {
	u, err := uuid.NewV4()
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to generate id for server: %v", err)
	}
	id := u.String()
	if err := diskutil.AtomicWritePrivateFile(idPath, []byte(id)); err != nil {
		return "", status.Errorf(codes.Internal, "failed to persist server id on path: %v", err)
	}
	return id, nil
}

// validateTemplateVariesWithKeyID renders the template with two distinct key IDs and
// returns an error if the outputs are identical (meaning the template ignores .KeyID,
// which would cause all keys to collide on the same storage slot).
func validateTemplateVariesWithKeyID(tpl *template.Template) error {
	render := func(keyID string) (string, error) {
		var buf bytes.Buffer
		if err := tpl.Execute(&buf, struct {
			TrustDomain string
			KeyID       string
		}{TrustDomain: "example-org", KeyID: keyID}); err != nil {
			return "", err
		}
		return buf.String(), nil
	}
	a, err := render("__probe_a__")
	if err != nil {
		return err
	}
	b, err := render("__probe_b__")
	if err != nil {
		return err
	}
	if a == b {
		return fmt.Errorf("must vary with .KeyID to avoid storage collisions (got %q for both probe values)", a)
	}
	return nil
}

// keyTypeFromSigner returns the SPIRE key type corresponding to a crypto.Signer's
// underlying key material. Returns false if the type is unrecognised.
func keyTypeFromSigner(signer crypto.Signer) (keymanagerv1.KeyType, bool) {
	switch k := signer.Public().(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return keymanagerv1.KeyType_EC_P256, true
		case elliptic.P384():
			return keymanagerv1.KeyType_EC_P384, true
		}
	case *rsa.PublicKey:
		switch k.N.BitLen() {
		case 2048:
			return keymanagerv1.KeyType_RSA_2048, true
		case 4096:
			return keymanagerv1.KeyType_RSA_4096, true
		}
	}
	return keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE, false
}
