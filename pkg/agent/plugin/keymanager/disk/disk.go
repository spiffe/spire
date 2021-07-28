package disk

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/hashicorp/hcl"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	keymanagerbase "github.com/spiffe/spire/pkg/agent/plugin/keymanager/base"
	catalog "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *KeyManager) catalog.BuiltIn {
	return catalog.MakeBuiltIn("disk",
		keymanagerv1.KeyManagerPluginServer(p),
		configv1.ConfigServiceServer(p))
}

type configuration struct {
	Directory string `hcl:"directory"`
}

type KeyManager struct {
	*keymanagerbase.Base
	configv1.UnimplementedConfigServer

	mu     sync.Mutex
	config *configuration
}

func New() *KeyManager {
	m := &KeyManager{}
	m.Base = keymanagerbase.New(keymanagerbase.Funcs{
		WriteEntries: m.writeEntries,
	})
	return m
}

func (m *KeyManager) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(configuration)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if config.Directory == "" {
		return nil, status.Error(codes.InvalidArgument, "directory must be configured")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.configure(config); err != nil {
		return nil, err
	}

	return &configv1.ConfigureResponse{}, nil
}

func (m *KeyManager) configure(config *configuration) error {
	// Only load entry information on first configure
	if m.config == nil {
		if err := m.loadEntries(config.Directory); err != nil {
			return err
		}
	}

	m.config = config
	return nil
}

func (m *KeyManager) loadEntries(dir string) error {
	// Load the entries from the keys file.
	entries, err := loadEntries(keysPath(dir))
	if err != nil {
		return err
	}

	// Load the key from the deprecated key path. ONLY add this key to the
	// entries list if there is not an entry for it already.
	// TODO: stop doing this in 1.1
	entry, err := loadDeprecatedKey(deprecatedKeyPath(dir))
	switch {
	case err != nil:
		return err
	case entry != nil:
		if !hasKey(entries, entry.PrivateKey) {
			entries = append(entries, entry)
		}
	}

	m.Base.SetEntries(entries)
	return nil
}

func (m *KeyManager) writeEntries(ctx context.Context, allEntries []*keymanagerbase.KeyEntry, newEntry *keymanagerbase.KeyEntry) error {
	m.mu.Lock()
	config := m.config
	m.mu.Unlock()

	if config == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}

	// For the 1.0 release, we need to continue persisting the last key to
	// the old deprecated key path so that we can safely downgrade the agent
	// back to 0.12.x if necessary.
	// TODO: stop doing this in 1.1 and remove the old key
	if err := writeDeprecatedKey(deprecatedKeyPath(config.Directory), newEntry.PrivateKey); err != nil {
		return err
	}

	return writeEntries(keysPath(config.Directory), allEntries)
}

type entriesData struct {
	Keys map[string][]byte `json:"keys"`
}

func loadEntries(path string) ([]*keymanagerbase.KeyEntry, error) {
	jsonBytes, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	data := new(entriesData)
	if err := json.Unmarshal(jsonBytes, data); err != nil {
		return nil, status.Errorf(codes.Internal, "unable to decode keys JSON: %v", err)
	}

	var entries []*keymanagerbase.KeyEntry
	for id, keyBytes := range data.Keys {
		key, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to parse key %q: %v", id, err)
		}
		entry, err := keymanagerbase.MakeKeyEntryFromKey(id, key)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to make entry %q: %v", id, err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func writeEntries(path string, entries []*keymanagerbase.KeyEntry) error {
	data := &entriesData{
		Keys: make(map[string][]byte),
	}
	for _, entry := range entries {
		keyBytes, err := x509.MarshalPKCS8PrivateKey(entry.PrivateKey)
		if err != nil {
			return err
		}
		data.Keys[entry.Id] = keyBytes
	}

	jsonBytes, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal entries: %v", err)
	}

	if err := diskutil.AtomicWriteFile(path, jsonBytes, 0600); err != nil {
		return status.Errorf(codes.Internal, "unable to write entries: %v", err)
	}

	return nil
}

func writeDeprecatedKey(path string, key crypto.Signer) error {
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		// Only need to write out ECDSA keys. Agent only uses ECDSA for the
		// time being and can't change until the v0 key manager interface is
		// deprecated with 1.1.
		// TODO: We can phase out support for the deprecated key path at the
		// same time (since we won't have to support a roll back to a version
		// before 1.0).
		return nil
	}

	data, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to marshal deprecated key: %v", err)
	}

	if err := diskutil.AtomicWriteFile(path, data, 0600); err != nil {
		return status.Errorf(codes.Internal, "failed to write deprecated key: %v", err)
	}

	return nil
}

func loadDeprecatedKey(path string) (*keymanagerbase.KeyEntry, error) {
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, status.Errorf(codes.InvalidArgument, "failed loading deprecated key: %v", err)
	}

	key, err := x509.ParseECPrivateKey(data)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed unmarshalling deprecated key: %v", err)
	}

	return keymanagerbase.MakeKeyEntryFromKey("agent-svid-deprecated", key)
}

func keysPath(dir string) string {
	return filepath.Join(dir, "keys.json")
}

func deprecatedKeyPath(dir string) string {
	return filepath.Join(dir, "svid.key")
}

func hasKey(entries []*keymanagerbase.KeyEntry, key crypto.Signer) bool {
	for _, entry := range entries {
		if equal, err := cryptoutil.PublicKeyEqual(entry.PrivateKey.Public(), key.Public()); err == nil && equal {
			return true
		}
	}
	return false
}
