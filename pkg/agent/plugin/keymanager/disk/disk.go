package disk

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	keymanagerbase "github.com/spiffe/spire/pkg/agent/plugin/keymanager/base"
	catalog "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/diskutil"
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
	Directory string `hcl:"directory"`
}

type KeyManager struct {
	*keymanagerbase.Base
	configv1.UnimplementedConfigServer

	log hclog.Logger

	mu     sync.Mutex
	config *configuration
}

func newKeyManager(generator Generator) *KeyManager {
	m := &KeyManager{}
	m.Base = keymanagerbase.New(keymanagerbase.Config{
		Generator:    generator,
		WriteEntries: m.writeEntries,
	})
	return m
}

func (m *KeyManager) SetLogger(log hclog.Logger) {
	m.log = log
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

	if err := diskutil.AtomicWritePrivateFile(path, jsonBytes); err != nil {
		return status.Errorf(codes.Internal, "unable to write entries: %v", err)
	}

	return nil
}

func keysPath(dir string) string {
	return filepath.Join(dir, "keys.json")
}
