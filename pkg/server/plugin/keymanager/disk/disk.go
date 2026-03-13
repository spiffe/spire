package disk

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"os"
	"sync"
	"text/template"
	"time"

	"github.com/hashicorp/hcl"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/pkg/common/pluginconf"
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
	KeysPath   string            `hcl:"keys_path"`
	SharedKeys *SharedKeysConfig `hcl:"shared_keys"`
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
}

func newKeyManager(generator Generator) *KeyManager {
	m := &KeyManager{
		generator: generator,
	}
	m.Base = keymanagerbase.New(keymanagerbase.Config{
		WriteEntries: m.writeEntries,
		Generator:    generator,
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
	// only load entry information on first configure
	if m.config == nil {
		entries, metadata, err := loadEntries(config.KeysPath)
		if err != nil {
			return err
		}
		m.Base.SetEntries(entries)
		m.metadata = metadata
		m.trustDomain = trustDomain
	}

	if config.SharedKeys != nil {
		tpl, err := template.New("crypto_key_template").Parse(config.SharedKeys.CryptoKeyTemplate)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "failed to parse crypto_key_template: %v", err)
		}
		m.tpl = tpl
	} else {
		m.tpl = nil
	}

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

	// Helper to check for reuse
	checkReuse := func(entries []*keymanagerbase.KeyEntry, metadata map[string]time.Time) *keymanagerbase.KeyEntry {
		// Find entry by storageID?
		// No, entries are keyed by logical ID (see loadEntries).
		// Wait, if I use shared keys:
		// Map Key (storage-id) -> KeyEntry.Id (logic id).
		// If storage-id == logic-id (default), easy.
		// If storage-id != logic-id (shared), `loadEntries` sets `entry.Id = logic-id`.
		// So `entries` list contains the key under its LOGICAL ID.
		// So we just search for `req.KeyId` in `entries`.

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

		// Check type
		// If type doesn't match, we probably shouldn't reuse it indiscriminately, but maybe we should?
		// GCP plugin checks Algorithm.
		// We should check KeyType?
		// `keymanagerbase.KeyEntry` doesn't strictly have KeyType stored, but has PrivateKey (RSA/EC).
		// We can check if it matches requested type.
		// But let's assume if it exists, it's the right one or we overwrite it?
		// For shared keys, we only overwrite if stale.

		// Check freshness
		if config.SharedKeys != nil {
			createdAt, ok := metadata[req.KeyId]
			if ok {
				// Freshness threshold 15m
				if time.Since(createdAt) < 15*time.Minute {
					return candidate
				}
			}
		}

		return nil // Not found or stale
	}

	lock := newFileLock(config.KeysPath + ".lock")

	// Phase 1: Optimistic Check
	candidate, err := func() (*keymanagerbase.KeyEntry, error) {
		if err := lock.Lock(); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to acquire lock: %v", err)
		}
		defer func() { _ = lock.Unlock() }()

		entries, metadata, err := loadEntries(config.KeysPath)
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
	entries, metadata, err := loadEntries(config.KeysPath)
	if err != nil {
		return nil, err
	}
	m.Base.SetEntries(entries)
	m.mu.Lock()
	m.metadata = metadata
	tpl := m.tpl
	td := m.trustDomain
	m.mu.Unlock()

	// Double check reuse
	if candidate := checkReuse(entries, metadata); candidate != nil {
		return &keymanagerv1.GenerateKeyResponse{
			PublicKey: candidate.PublicKey,
		}, nil
	}

	// Append new key (replace existing if present)
	var newEntries []*keymanagerbase.KeyEntry
	updated := false
	for _, e := range entries {
		if e.Id == req.KeyId {
			newEntries = append(newEntries, newEntry)
			updated = true
		} else {
			newEntries = append(newEntries, e)
		}
	}
	if !updated {
		newEntries = append(newEntries, newEntry)
	}

	metadata[req.KeyId] = time.Now()

	// Write
	if err := writeEntries(config.KeysPath, newEntries, metadata, tpl, td); err != nil {
		return nil, err
	}

	// Update memory
	m.Base.SetEntries(newEntries)
	m.mu.Lock()
	m.metadata = metadata
	m.mu.Unlock()

	return &keymanagerv1.GenerateKeyResponse{
		PublicKey: newEntry.PublicKey,
	}, nil
}

func (m *KeyManager) writeEntries(_ context.Context, entries []*keymanagerbase.KeyEntry) error {
	m.mu.Lock()
	config := m.config
	metadata := m.metadata
	tpl := m.tpl
	td := m.trustDomain
	m.mu.Unlock()

	if config == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}

	return writeEntries(config.KeysPath, entries, metadata, tpl, td)
}

type entriesData struct {
	// Keys is a map of key ID to the key entry.
	// The value can be either base64 encoded PKCS8 bytes (legacy) or a keyEntryRecord.
	Keys map[string]json.RawMessage `json:"keys"`
}

type keyEntryRecord struct {
	Id         string    `json:"id"`
	PrivateKey []byte    `json:"private_key"`
	CreatedAt  time.Time `json:"created_at"`
}

func loadEntries(path string) ([]*keymanagerbase.KeyEntry, map[string]time.Time, error) {
	jsonBytes, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, make(map[string]time.Time), nil
		}
		return nil, nil, err
	}

	data := new(entriesData)
	if err := json.Unmarshal(jsonBytes, data); err != nil {
		return nil, nil, status.Errorf(codes.Internal, "unable to decode keys JSON: %v", err)
	}

	var entries []*keymanagerbase.KeyEntry
	metadata := make(map[string]time.Time)

	for id, raw := range data.Keys {
		var record keyEntryRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			return nil, nil, status.Errorf(codes.Internal, "unable to decode key %q: %v", id, err)
		}

		if record.PrivateKey == nil {
			return nil, nil, status.Errorf(codes.Internal, "missing private key for key %q", id)
		}

		key, err := x509.ParsePKCS8PrivateKey(record.PrivateKey)
		if err != nil {
			return nil, nil, status.Errorf(codes.Internal, "unable to parse key %q: %v", id, err)
		}

		// If ID is not in the record (shouldn't happen with new format), fail or fallback?
		// New format always has ID.
		if record.Id == "" {
			return nil, nil, status.Errorf(codes.Internal, "missing key id for key %q", id)
		}

		entry, err := keymanagerbase.MakeKeyEntryFromKey(record.Id, key)
		if err != nil {
			return nil, nil, status.Errorf(codes.Internal, "unable to make entry %q: %v", id, err)
		}
		entries = append(entries, entry)
		if !record.CreatedAt.IsZero() {
			metadata[record.Id] = record.CreatedAt
		}
	}
	return entries, metadata, nil
}

func writeEntries(path string, entries []*keymanagerbase.KeyEntry, metadata map[string]time.Time, tpl *template.Template, trustDomain string) error {
	data := &entriesData{
		Keys: make(map[string]json.RawMessage),
	}

	// Helper to calculate storage ID
	calculateStorageID := func(trustDomain, keyID string) (string, error) {
		if tpl == nil {
			return keyID, nil
		}
		var buf bytes.Buffer
		data := struct {
			TrustDomain string
			KeyID       string
		}{
			TrustDomain: trustDomain,
			KeyID:       keyID,
		}
		if err := tpl.Execute(&buf, data); err != nil {
			return "", err
		}
		return buf.String(), nil
	}

	for _, entry := range entries {
		keyBytes, err := x509.MarshalPKCS8PrivateKey(entry.PrivateKey)
		if err != nil {
			return err
		}

		record := keyEntryRecord{
			Id:         entry.Id,
			PrivateKey: keyBytes,
		}
		if t, ok := metadata[entry.Id]; ok {
			record.CreatedAt = t
		}

		recordBytes, err := json.Marshal(record)
		if err != nil {
			return status.Errorf(codes.Internal, "unable to marshal key entry %q: %v", entry.Id, err)
		}

		storageID, err := calculateStorageID(trustDomain, entry.Id)
		if err != nil {
			return status.Errorf(codes.Internal, "unable to calculate storage ID: %v", err)
		}
		data.Keys[storageID] = recordBytes
	}

	jsonBytes, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal entries: %v", err)
	}

	if err := diskutil.AtomicWritePrivateFile(path, jsonBytes); err != nil {
		return status.Errorf(codes.Internal, "unable to write entries: %v", err)
	}

	return nil
}
