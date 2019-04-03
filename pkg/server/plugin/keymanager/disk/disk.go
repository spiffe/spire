package disk

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/base"
	"github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/keymanager"
)

func BuiltIn() catalog.Plugin {
	return builtIn(New())
}

func builtIn(p *KeyManager) catalog.Plugin {
	return catalog.MakePlugin("disk", keymanager.PluginServer(p))
}

type configuration struct {
	KeysPath string `hcl:"keys_path"`
}

type KeyManager struct {
	*base.Base

	mu     sync.Mutex
	config *configuration
}

func New() *KeyManager {
	m := &KeyManager{}
	m.Base = base.New(base.Impl{
		ErrorFn: newError,
		WriteFn: m.saveEntries,
	})
	return m
}

func (m *KeyManager) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	config := new(configuration)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, newError("unable to decode configuration: %v", err)
	}

	if config.KeysPath == "" {
		return nil, newError("keys_path is required")
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

func (m *KeyManager) saveEntries(ctx context.Context, entries []*base.KeyEntry) error {
	m.mu.Lock()
	config := m.config
	m.mu.Unlock()

	if config == nil {
		return newError("not configured")
	}

	return writeEntries(config.KeysPath, entries)
}

type entriesData struct {
	Keys map[string][]byte `json:"keys"`
}

func loadEntries(path string) ([]*base.KeyEntry, error) {
	jsonBytes, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	data := new(entriesData)
	if err := json.Unmarshal(jsonBytes, data); err != nil {
		return nil, newError("unable to decode keys JSON: %v", err)
	}

	var entries []*base.KeyEntry
	for id, keyBytes := range data.Keys {
		key, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, newError("unable to parse key %q: %v", id, err)
		}
		entry, err := base.MakeKeyEntryFromKey(id, key)
		if err != nil {
			return nil, newError("unable to make entry %q: %v", id, err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func writeEntries(path string, entries []*base.KeyEntry) error {
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
		return newError("unable to marshal entries: %v", err)
	}

	if err := diskutil.AtomicWriteFile(path, jsonBytes, 0644); err != nil {
		return newError("unable to write entries: %v", err)
	}

	return nil
}

func newError(format string, args ...interface{}) error {
	return fmt.Errorf("keymanager(disk): "+format, args...)
}
