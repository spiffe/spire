package memory

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	keymanagerbase "github.com/spiffe/spire/pkg/server/plugin/keymanager/base"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	keymanagerv0 "github.com/spiffe/spire/proto/spire/server/keymanager/v0"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *KeyManager) catalog.Plugin {
	return catalog.MakePlugin("memory", keymanagerv0.PluginServer(p))
}

type KeyManager struct {
	*keymanagerbase.Base
}

func New() *KeyManager {
	return &KeyManager{
		Base: keymanagerbase.New(keymanagerbase.Funcs{}),
	}
}

func (m *KeyManager) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return &plugin.ConfigureResponse{}, nil
}

func (m *KeyManager) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}
