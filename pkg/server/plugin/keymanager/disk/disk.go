package disk

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"os"
	"sync"

	"github.com/hashicorp/hcl"
	catalog "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/diskutil"
	keymanagerbase "github.com/spiffe/spire/pkg/server/plugin/keymanager/base"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	keymanagerv0 "github.com/spiffe/spire/proto/spire/server/keymanager/v0"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *KeyManager) catalog.Plugin {
	return catalog.MakePlugin("disk", keymanagerv0.PluginServer(p))
}

type configuration struct {
	KeysPath string `hcl:"keys_path"`
}

type KeyManager struct {
	*keymanagerbase.Base

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

func (m *KeyManager) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	config := new(configuration)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if config.KeysPath == "" {
		return nil, status.Error(codes.InvalidArgument, "keys_path is required")
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
		entries, err := loadEntries(config.KeysPath)
		if err != nil {
			return err
		}
		m.Base.SetEntries(entries)
	}

	m.config = config
	return nil
}

func (m *KeyManager) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}

func (m *KeyManager) writeEntries(ctx context.Context, entries []*keymanagerbase.KeyEntry) error {
	m.mu.Lock()
	config := m.config
	m.mu.Unlock()

	if config == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}

	return writeEntries(config.KeysPath, entries)
}

type entriesData struct {
	Keys map[string][]byte `json:"keys"`
}

func loadEntries(path string) ([]*keymanagerbase.KeyEntry, error) {
	jsonBytes, err := ioutil.ReadFile(path)
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

	if err := diskutil.AtomicWriteFile(path, jsonBytes, 0644); err != nil {
		return status.Errorf(codes.Internal, "unable to write entries: %v", err)
	}

	return nil
}
